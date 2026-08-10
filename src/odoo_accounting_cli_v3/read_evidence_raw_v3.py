"""Strict, offline contracts for full-raw read evidence.

This module validates internal structure and deterministic bindings only.  It
does not collect evidence, verify a producer attestation, contact Odoo/Pi, or
turn a structurally valid document into external/Goal-admissible evidence.
Pi full-raw exchanges remain the responsibility of the existing
``PiEvidenceVerifier`` and are deliberately rejected here.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import uuid
from datetime import datetime
from typing import Any, Mapping

from .contracts import ContractError, validate_value
from .receipts import (
    READ_RECEIPT_PURPOSE,
    SIGNATURE_VERSION,
    read_request_digest,
    valid_read_runtime_binding,
)
from .registry import Capability, RegistryError, registry_digest, validate_registry


FULL_RAW_EVIDENCE_SCHEMA = (
    "odoo-accounting-cli-v3.read-evidence-full-raw.v3"
)
FULL_RAW_VALIDATION_REPORT_SCHEMA = (
    "odoo-accounting-cli-v3.read-evidence-full-raw-validation.v1"
)
SCOPE_SCHEMA = "odoo-accounting-cli-v3.read-evidence-scope.v3"
TRUSTED_SOURCE_ADAPTER_BLOCKER = (
    "trusted raw-source producer/attestor is not implemented; contract "
    "validation alone is not external or Goal-admissible evidence"
)
ORACLE_READ_ONLY_ATTESTATION_BLOCKER = (
    "accounting oracle implementation identity, query semantics, company-scoped "
    "execution, and read-only transaction are not independently attested"
)
PI_TRUSTED_VERIFIER_BLOCKER = (
    "Pi full-raw evidence must be verified by PiEvidenceVerifier"
)

__all__ = (
    "FULL_RAW_EVIDENCE_SCHEMA",
    "FULL_RAW_VALIDATION_REPORT_SCHEMA",
    "SCOPE_SCHEMA",
    "TRUSTED_SOURCE_ADAPTER_BLOCKER",
    "ORACLE_READ_ONLY_ATTESTATION_BLOCKER",
    "PI_TRUSTED_VERIFIER_BLOCKER",
    "FullRawEvidenceError",
    "validate_full_raw_evidence",
)

MAX_DOCUMENT_BYTES = 16 * 1024 * 1024
MAX_JSON_DEPTH = 32
MAX_JSON_NODES = 100_000
MAX_JSON_STRING_BYTES = 1024 * 1024
MAX_QUERY_BYTES = 128 * 1024
MAX_CAPABILITIES = 256
MAX_CASES_PER_CAPABILITY = 8
MAX_SOURCE_RECORDS = 10_000
MAX_ALLOWED_COMPANIES = 64
MAX_IDENTIFIER_BYTES = 256
MAX_TEXT_BYTES = 256 * 1024

EVIDENCE_KINDS = (
    "accounting_oracle",
    "live_odoo",
    "release_identity",
    "security_negative",
)

SECURITY_CASES = (
    ("acl_deny", "odoo_acl_denied"),
    ("cross_company", "company_binding_rejected"),
    ("expired", "authentication_expired"),
    ("replay", "authentication_replayed"),
    ("tamper_parameters", "authentication_tampered"),
)
_OUTPUT_COMPANY_BINDING_KIND = {
    "acct.ap.open_items.v1": "single_filter",
    "acct.ar.open_items.v1": "single_filter",
    "acct.diagnostics.operation_read.v1": "diagnostics",
    "acct.gl.trial_balance.v1": "none",
    "acct.move.document_post_eligibility.v1": "move_eligibility",
    "acct.move.draft_cancel_eligibility.v1": "move_eligibility",
    "acct.multicompany.consolidated_read.v1": "multicompany",
    "acct.multicurrency.balance_read.v1": "multicurrency",
    "acct.refund.draft_cancel_eligibility.v1": "refund_eligibility",
    "acct.refund.post_reconcile_eligibility.v1": "refund_eligibility",
    "acct.registry.list.v1": "none",
    "acct.report.financial_read.v1": "none",
    "acct.tax.report_read.v1": "none",
}
_ORACLE_TECHNICAL_COMPANY_CAPABILITIES = frozenset(
    {
        "acct.multicompany.consolidated_read.v1",
        "acct.multicurrency.balance_read.v1",
    }
)
_ORACLE_TECHNICAL_COMPANY_FIELDS = frozenset(
    {"rate_company_id", "source_company_id"}
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_CAPABILITY_ID = re.compile(
    r"^acct\.[a-z0-9_]+\.[a-z0-9_]+\.v[1-9][0-9]*$"
)
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_RELEASE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,191}$")
_RFC3339 = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
)

_ROOT_FIELDS = frozenset(
    {
        "capabilities",
        "evidence_kind",
        "release_identity",
        "run_id",
        "schema_version",
        "scope_sha256",
    }
)
_SCOPE_FIELDS = frozenset(
    {
        "capability_contracts",
        "company_ids",
        "database_name",
        "database_uuid",
        "environment",
        "release_identity",
        "run_id",
        "schema_version",
    }
)
_CAPABILITY_FIELDS = frozenset(
    {"capability_contract_sha256", "capability_id", "cases"}
)
_RELEASE_IDENTITY_FIELDS = frozenset(
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
_REQUEST_FIELDS = frozenset(
    {
        "allowed_company_ids",
        "auth_token_id",
        "capability_channel",
        "capability_contract_sha256",
        "capability_id",
        "company_id",
        "database_name",
        "database_uuid",
        "environment",
        "odoo_instance_id",
        "parameters",
        "parameters_sha256",
        "principal",
        "registry_digest",
        "release_digest",
        "release_identity_sha256",
        "request_digest",
        "request_id",
        "run_id",
        "scope_sha256",
        "user_id",
    }
)
_RESPONSE_FIELDS = frozenset(
    {"record_count", "request_id", "result_body", "result_sha256", "status"}
)
_RECEIPT_FIELDS = frozenset(
    {
        "capability_channel",
        "capability_id",
        "company_id",
        "database_name",
        "database_uuid",
        "environment",
        "id",
        "observed_at",
        "odoo_instance_id",
        "record_count",
        "registry_digest",
        "release_digest",
        "request_digest",
        "result_digest",
        "signature",
        "signature_key_id",
        "signature_purpose",
        "signature_version",
        "user_id",
    }
)
_EXECUTION_FIELDS = frozenset(
    {"receipt", "request", "response", "source_witness"}
)
_SOURCE_WITNESS_FIELDS = frozenset(
    {
        "boundary_mode",
        "odoo_write_count",
        "post_state_sha256",
        "pre_state_sha256",
        "read_only",
        "receipt_sha256",
        "request_sha256",
        "response_sha256",
        "rolled_back",
        "source_type",
        "write_statement_count",
    }
)
_LIVE_CASE_FIELDS = frozenset({"case_id", "execution"})
_ORACLE_CASE_FIELDS = frozenset(
    {
        "case_id",
        "execution",
        "oracle_definition",
        "oracle_result",
        "oracle_result_sha256",
        "oracle_witness",
        "source_records",
        "source_records_sha256",
    }
)
_ORACLE_WITNESS_FIELDS = frozenset(
    {
        "boundary_mode",
        "executed_at",
        "observed_result_sha256",
        "oracle_definition_sha256",
        "oracle_input_sha256",
        "oracle_result_sha256",
        "oracle_type",
        "post_state_sha256",
        "pre_state_sha256",
        "read_only",
        "rolled_back",
        "source_record_count",
        "source_records_sha256",
        "write_count",
    }
)
_ORACLE_COMMON_FIELDS = frozenset(
    {"oracle_code_sha256", "oracle_id", "oracle_type"}
)
_ORACLE_DEFINITION_FIELDS = {
    "postgresql_sql": _ORACLE_COMMON_FIELDS
    | {
        "query_parameters",
        "query_sha256",
        "query_text",
        "statement_type",
    },
    "business_rule": _ORACLE_COMMON_FIELDS
    | {"rule_inputs", "rule_inputs_sha256", "ruleset_sha256"},
    "registry_contract": _ORACLE_COMMON_FIELDS
    | {"registry_digest", "registry_schema_sha256"},
    "durable_store": _ORACLE_COMMON_FIELDS
    | {"store_schema_sha256", "store_snapshot_sha256"},
}
_SECURITY_CASE_FIELDS = frozenset(
    {
        "auth_witness",
        "case_id",
        "exit_code",
        "expected_error_code",
        "request",
        "request_sha256",
        "response",
        "response_sha256",
        "side_effect_witness",
    }
)
_AUTH_WITNESS_FIELDS = frozenset(
    {
        "attempt_count",
        "bound_parameters_sha256",
        "expires_at",
        "not_before",
        "observed_at",
        "odoo_permission_granted",
    }
)
_SECURITY_RESPONSE_FIELDS = frozenset(
    {
        "error_code",
        "error_message",
        "receipt",
        "request_id",
        "result",
        "status",
    }
)
_SIDE_EFFECT_FIELDS = frozenset(
    {
        "business_state_post_sha256",
        "business_state_pre_sha256",
        "cli_business_write_count",
        "odoo_write_count",
        "postgresql_write_count",
        "receipt_count",
        "result_count",
    }
)
_RELEASE_CASE_FIELDS = frozenset(
    {
        "capability_contract_sha256",
        "case_id",
        "observed_release_identity",
        "release_identity_sha256",
        "scope_sha256",
    }
)


class FullRawEvidenceError(ValueError):
    """Raised when a full-raw document violates its offline contract."""


def _canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except UnicodeEncodeError as exc:
        raise FullRawEvidenceError(
            "full-raw value is not valid UTF-8"
        ) from exc
    except (TypeError, ValueError, RecursionError) as exc:
        raise FullRawEvidenceError("full-raw value is not canonical JSON") from exc


def _utf8_length(value: str, label: str) -> int:
    try:
        return len(value.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise FullRawEvidenceError(f"{label} is not valid UTF-8") from exc


def _json_digest(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _json_equal(left: Any, right: Any) -> bool:
    return hmac.compare_digest(_canonical_bytes(left), _canonical_bytes(right))


def _measure_document(value: Any) -> tuple[int, int]:
    stack: list[tuple[Any, int]] = [(value, 1)]
    nodes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES:
            raise FullRawEvidenceError("full-raw document exceeds its node limit")
        if depth > MAX_JSON_DEPTH:
            raise FullRawEvidenceError("full-raw document exceeds its depth limit")
        if type(current) is dict:
            for key, child in current.items():
                if type(key) is not str:
                    raise FullRawEvidenceError("full-raw object keys must be strings")
                if _utf8_length(key, "full-raw object key") > MAX_IDENTIFIER_BYTES:
                    raise FullRawEvidenceError("full-raw object key is too large")
                stack.append((child, depth + 1))
        elif type(current) is list:
            for child in current:
                stack.append((child, depth + 1))
        elif type(current) is str:
            if (
                _utf8_length(current, "full-raw string")
                > MAX_JSON_STRING_BYTES
            ):
                raise FullRawEvidenceError("full-raw string exceeds its size limit")
        elif current is None or type(current) in {bool, int, float}:
            continue
        else:
            raise FullRawEvidenceError("full-raw document contains non-JSON data")
    size = len(_canonical_bytes(value))
    if size > MAX_DOCUMENT_BYTES:
        raise FullRawEvidenceError("full-raw document exceeds its byte limit")
    return nodes, size


def _object(value: Any, label: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise FullRawEvidenceError(f"{label} must be an object")
    return value


def _exact_fields(
    value: Any, fields: frozenset[str] | set[str], label: str
) -> dict[str, Any]:
    result = _object(value, label)
    missing = set(fields) - set(result)
    extra = set(result) - set(fields)
    if missing or extra:
        raise FullRawEvidenceError(
            f"{label} fields invalid; missing={sorted(missing)}, extra={sorted(extra)}"
        )
    return result


def _bounded_text(
    value: Any,
    label: str,
    *,
    maximum: int = MAX_TEXT_BYTES,
    multiline: bool = False,
) -> str:
    permitted_controls = {"\t", "\n", "\r"} if multiline else set()
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or _utf8_length(value, label) > maximum
        or any(
            (ord(character) < 32 and character not in permitted_controls)
            or ord(character) == 127
            for character in value
        )
    ):
        raise FullRawEvidenceError(f"{label} is invalid")
    return value


def _identifier(value: Any, label: str) -> str:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        raise FullRawEvidenceError(f"{label} is invalid")
    return value


def _digest(value: Any, label: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise FullRawEvidenceError(f"{label} must be a lowercase SHA-256")
    return value


def _positive_integer(value: Any, label: str) -> int:
    if type(value) is not int or value <= 0:
        raise FullRawEvidenceError(f"{label} must be a positive integer")
    return value


def _nonnegative_integer(value: Any, label: str) -> int:
    if type(value) is not int or value < 0:
        raise FullRawEvidenceError(f"{label} must be a non-negative integer")
    return value


def _timestamp(value: Any, label: str) -> tuple[str, datetime]:
    if type(value) is not str or _RFC3339.fullmatch(value) is None:
        raise FullRawEvidenceError(f"{label} must be canonical UTC RFC3339")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise FullRawEvidenceError(f"{label} is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise FullRawEvidenceError(f"{label} must be timezone-aware")
    return value, parsed


def _database_uuid(value: Any, label: str) -> str:
    if type(value) is not str:
        raise FullRawEvidenceError(f"{label} is invalid")
    try:
        parsed = str(uuid.UUID(value))
    except (AttributeError, TypeError, ValueError) as exc:
        raise FullRawEvidenceError(f"{label} is invalid") from exc
    if parsed != value:
        raise FullRawEvidenceError(f"{label} must be canonical")
    return value


def _validate_release_identity(value: Any, label: str) -> dict[str, Any]:
    identity = _exact_fields(value, _RELEASE_IDENTITY_FIELDS, label)
    if type(identity["commit"]) is not str or _COMMIT.fullmatch(identity["commit"]) is None:
        raise FullRawEvidenceError(f"{label} commit is invalid")
    for field in (
        "manifest_sha256",
        "package_sha256",
        "registry_digest",
    ):
        _digest(identity[field], f"{label} {field}")
    if (
        type(identity["release"]) is not str
        or _RELEASE.fullmatch(identity["release"]) is None
        or type(identity["version"]) is not str
        or _RELEASE.fullmatch(identity["version"]) is None
        or identity["verified"] is not True
    ):
        raise FullRawEvidenceError(f"{label} release/version verification is invalid")
    return identity


def _validate_expected_context(
    *,
    expected_registry: tuple[Capability, ...],
    expected_scope: Mapping[str, Any],
    expected_scope_sha256: str,
    expected_release_identity: Mapping[str, Any],
    expected_run_id: str,
) -> tuple[
    dict[str, str],
    dict[str, dict[str, Any]],
    dict[str, Any],
    dict[str, Any],
]:
    identity = _validate_release_identity(
        expected_release_identity, "expected release identity"
    )
    if (
        type(expected_registry) is not tuple
        or not expected_registry
        or len(expected_registry) > MAX_CAPABILITIES
        or any(type(capability) is not Capability for capability in expected_registry)
    ):
        raise FullRawEvidenceError(
            "expected registry must be a bounded validated Capability tuple"
        )
    try:
        registry_entries = [capability.data for capability in expected_registry]
        validated_registry = validate_registry(
            {"schema_version": 1, "capabilities": registry_entries}
        )
        observed_registry_digest = registry_digest(validated_registry)
        registry_entries = [capability.data for capability in validated_registry]
    except (
        KeyError,
        RegistryError,
        TypeError,
        ValueError,
        RecursionError,
    ) as exc:
        raise FullRawEvidenceError("expected registry is invalid") from exc
    if observed_registry_digest != identity["registry_digest"]:
        raise FullRawEvidenceError("expected registry digest mismatch")
    if any(type(entry) is not dict for entry in registry_entries):
        raise FullRawEvidenceError("expected registry entries are invalid")
    read_entries = [
        entry for entry in registry_entries if entry.get("access") == "read"
    ]
    if any(
        type(entry.get("id")) is not str
        or _CAPABILITY_ID.fullmatch(entry["id"]) is None
        for entry in read_entries
    ):
        raise FullRawEvidenceError("expected registry read capability ID is invalid")
    read_capabilities = {
        entry["id"]: entry
        for entry in read_entries
    }
    if (
        not read_capabilities
        or len(read_capabilities) > MAX_CAPABILITIES
        or len(read_capabilities) != len(read_entries)
    ):
        raise FullRawEvidenceError("expected registry read capabilities are invalid")
    contracts = {
        capability_id: _json_digest(capability)
        for capability_id, capability in read_capabilities.items()
    }
    scope = _exact_fields(expected_scope, _SCOPE_FIELDS, "expected scope")
    if scope["schema_version"] != SCOPE_SCHEMA:
        raise FullRawEvidenceError("expected scope schema is invalid")
    if (
        type(scope["capability_contracts"]) is not dict
        or scope["capability_contracts"] != contracts
    ):
        raise FullRawEvidenceError("expected scope capability contracts mismatch")
    companies = scope["company_ids"]
    if (
        type(companies) is not list
        or not companies
        or len(companies) > MAX_ALLOWED_COMPANIES
        or any(type(company) is not int or company <= 0 for company in companies)
        or companies != sorted(set(companies))
    ):
        raise FullRawEvidenceError("expected scope company_ids are invalid")
    _bounded_text(scope["database_name"], "expected scope database_name")
    _database_uuid(scope["database_uuid"], "expected scope database_uuid")
    if (
        type(scope["environment"]) is not str
        or scope["environment"] not in {"test", "sandbox", "production"}
    ):
        raise FullRawEvidenceError("expected scope environment is invalid")
    _identifier(expected_run_id, "expected run_id")
    if scope["run_id"] != expected_run_id:
        raise FullRawEvidenceError("expected scope run_id mismatch")
    _digest(expected_scope_sha256, "expected scope_sha256")
    canonical_scope_sha256 = hashlib.sha256(
        _canonical_bytes(scope) + b"\n"
    ).hexdigest()
    if expected_scope_sha256 != canonical_scope_sha256:
        raise FullRawEvidenceError("expected scope digest mismatch")
    scope_identity = _validate_release_identity(
        scope["release_identity"], "expected scope release identity"
    )
    if not _json_equal(scope_identity, identity):
        raise FullRawEvidenceError("expected scope release identity mismatch")
    return contracts, read_capabilities, scope, identity


def _validate_request(
    value: Any,
    *,
    capability_id: str,
    capability: dict[str, Any],
    contract: str,
    scope: dict[str, Any],
    scope_sha256: str,
    identity: dict[str, Any],
    run_id: str,
    allow_company_binding_failure: bool = False,
) -> dict[str, Any]:
    request = _exact_fields(value, _REQUEST_FIELDS, "full-raw request")
    if request["capability_id"] != capability_id:
        raise FullRawEvidenceError("full-raw request capability mismatch")
    if request["capability_contract_sha256"] != contract:
        raise FullRawEvidenceError("full-raw request contract mismatch")
    if request["run_id"] != run_id:
        raise FullRawEvidenceError("full-raw request run_id mismatch")
    if request["scope_sha256"] != scope_sha256:
        raise FullRawEvidenceError("full-raw request scope mismatch")
    expected_identity_sha256 = _json_digest(identity)
    if request["release_identity_sha256"] != expected_identity_sha256:
        raise FullRawEvidenceError("full-raw request release identity mismatch")
    if (
        request["registry_digest"] != identity["registry_digest"]
        or request["release_digest"] != identity["manifest_sha256"]
    ):
        raise FullRawEvidenceError("full-raw request release digest mismatch")
    if (
        request["database_name"] != scope["database_name"]
        or request["database_uuid"] != scope["database_uuid"]
        or request["environment"] != scope["environment"]
    ):
        raise FullRawEvidenceError("full-raw request database/environment mismatch")
    _database_uuid(request["database_uuid"], "full-raw request database_uuid")
    for field in (
        "auth_token_id",
        "odoo_instance_id",
        "principal",
        "request_id",
    ):
        _identifier(request[field], f"full-raw request {field}")
    company_id = _positive_integer(request["company_id"], "full-raw request company_id")
    user_id = _positive_integer(request["user_id"], "full-raw request user_id")
    allowed = request["allowed_company_ids"]
    if (
        type(allowed) is not list
        or not allowed
        or len(allowed) > MAX_ALLOWED_COMPANIES
        or any(type(company) is not int or company <= 0 for company in allowed)
        or allowed != sorted(set(allowed))
        or any(company not in scope["company_ids"] for company in allowed)
        or company_id not in scope["company_ids"]
    ):
        raise FullRawEvidenceError("full-raw request allowed companies are invalid")
    if not allow_company_binding_failure and company_id not in allowed:
        raise FullRawEvidenceError("full-raw request company binding mismatch")
    if not valid_read_runtime_binding(
        request["environment"], request["capability_channel"]
    ):
        raise FullRawEvidenceError("full-raw request runtime binding is invalid")
    parameters = request["parameters"]
    if type(parameters) is not dict:
        raise FullRawEvidenceError("full-raw request parameters must be an object")
    if request["parameters_sha256"] != _json_digest(parameters):
        raise FullRawEvidenceError("full-raw request parameters digest mismatch")
    try:
        validate_value(parameters, capability["input_schema"])
    except ContractError as exc:
        raise FullRawEvidenceError(
            "full-raw request parameters do not match the release input schema"
        ) from exc
    company_scope = capability["company_scope"]
    if company_scope in {"bound_company", "explicit_single_company"}:
        if parameters.get("company_id") != company_id:
            raise FullRawEvidenceError(
                "full-raw request parameter company binding mismatch"
            )
    elif company_scope == "allowed_companies":
        parameter_companies = parameters.get("company_ids")
        if (
            type(parameter_companies) is not list
            or not parameter_companies
            or any(company not in allowed for company in parameter_companies)
            or any(company not in scope["company_ids"] for company in parameter_companies)
        ):
            raise FullRawEvidenceError(
                "full-raw request parameter company binding mismatch"
            )
    else:
        raise FullRawEvidenceError("full-raw request company scope is invalid")
    expected_request_digest = read_request_digest(
        capability_id=capability_id,
        parameters=parameters,
        auth_token_id=request["auth_token_id"],
        principal=request["principal"],
        odoo_instance_id=request["odoo_instance_id"],
        database_name=request["database_name"],
        database_uuid=request["database_uuid"],
        company_id=company_id,
        user_id=user_id,
        registry_digest=request["registry_digest"],
        release_digest=request["release_digest"],
        environment=request["environment"],
        capability_channel=request["capability_channel"],
    )
    if request["request_digest"] != expected_request_digest:
        raise FullRawEvidenceError("full-raw request digest mismatch")
    return request


def _validate_response(value: Any, request: dict[str, Any]) -> dict[str, Any]:
    response = _exact_fields(value, _RESPONSE_FIELDS, "full-raw response")
    if response["request_id"] != request["request_id"]:
        raise FullRawEvidenceError("full-raw response request mismatch")
    if response["status"] != "ok" or type(response["result_body"]) is not dict:
        raise FullRawEvidenceError("full-raw response body/status is invalid")
    if "receipt" in response["result_body"]:
        raise FullRawEvidenceError("full-raw response body contains an embedded receipt")
    record_count = _nonnegative_integer(
        response["record_count"], "full-raw response record_count"
    )
    if response["result_sha256"] != _json_digest(response["result_body"]):
        raise FullRawEvidenceError("full-raw response result digest mismatch")
    page = response["result_body"].get("page")
    if type(page) is dict and page.get("total_count") != record_count:
        raise FullRawEvidenceError("full-raw response page count mismatch")
    return response


def _requested_company_ids(
    request: dict[str, Any], capability: dict[str, Any]
) -> frozenset[int]:
    company_scope = capability["company_scope"]
    if company_scope in {"bound_company", "explicit_single_company"}:
        return frozenset({request["company_id"]})
    if company_scope == "allowed_companies":
        return frozenset(request["parameters"]["company_ids"])
    raise FullRawEvidenceError("full-raw company scope is invalid")


def _require_company(value: Any, expected: int, label: str) -> None:
    if type(value) is not int or value != expected:
        raise FullRawEvidenceError(f"{label} company binding mismatch")


def _company_id_list(
    value: Any,
    *,
    permitted: frozenset[int],
    label: str,
    exact: bool = False,
) -> tuple[int, ...]:
    if (
        type(value) is not list
        or any(type(company_id) is not int for company_id in value)
        or value != sorted(set(value))
    ):
        raise FullRawEvidenceError(f"{label} company list is invalid")
    observed = tuple(value)
    if exact:
        if observed != tuple(sorted(permitted)):
            raise FullRawEvidenceError(f"{label} company coverage mismatch")
    elif any(company_id not in permitted for company_id in observed):
        raise FullRawEvidenceError(f"{label} company scope mismatch")
    return observed


def _validate_technical_rate_source(
    source: dict[str, Any],
    *,
    expected_currency_id: int,
    allow_no_rate_identity: bool,
    label: str,
    rate_company_id: int | None = None,
) -> None:
    if source["currency_id"] != expected_currency_id:
        raise FullRawEvidenceError(f"{label} currency binding mismatch")
    source_scope = source["source_scope"]
    source_company_id = source["source_company_id"]
    if source_scope == "no_rate_identity":
        if (
            not allow_no_rate_identity
            or source["source_model"] != "no_rate_identity"
            or source["effective_date"] is not None
            or source_company_id is not None
            or source["source_record_id"] is not None
        ):
            raise FullRawEvidenceError(f"{label} no-rate identity is invalid")
        return
    if source_scope not in {"company_specific", "global"}:
        raise FullRawEvidenceError(f"{label} company source scope is invalid")
    if (
        source["source_model"] != "res.currency.rate"
        or type(source["effective_date"]) is not str
    ):
        raise FullRawEvidenceError(f"{label} rate source is invalid")
    _positive_integer(source["source_record_id"], f"{label} source_record_id")
    if source_scope == "company_specific":
        observed_company_id = _positive_integer(
            source_company_id, f"{label} source_company_id"
        )
        if rate_company_id is not None and observed_company_id != rate_company_id:
            raise FullRawEvidenceError(f"{label} rate company binding mismatch")
    elif source_company_id is not None:
        raise FullRawEvidenceError(f"{label} global company binding mismatch")


def _validate_multicompany_output(
    result_body: dict[str, Any], request: dict[str, Any]
) -> None:
    requested = frozenset(request["parameters"]["company_ids"])
    _company_id_list(
        result_body["filters"]["company_ids"],
        permitted=requested,
        label="full-raw multicompany filters",
        exact=True,
    )
    companies = result_body["companies"]
    company_ids = [company["company_id"] for company in companies]
    _company_id_list(
        company_ids,
        permitted=requested,
        label="full-raw multicompany companies",
        exact=True,
    )
    for company in companies:
        company_id = company["company_id"]
        rate = company["translation_rate"]
        _require_company(
            rate["company_id"],
            company_id,
            "full-raw multicompany translation rate",
        )
        rate_company_id = _positive_integer(
            rate["rate_company_id"],
            "full-raw multicompany rate_company_id",
        )
        for field, currency_id, allow_identity in (
            ("source_technical_source", rate["source_currency_id"], True),
            (
                "presentation_technical_source",
                rate["presentation_currency_id"],
                rate["source_currency_id"] == rate["presentation_currency_id"],
            ),
        ):
            _validate_technical_rate_source(
                rate[field],
                expected_currency_id=currency_id,
                allow_no_rate_identity=allow_identity,
                rate_company_id=rate_company_id,
                label=f"full-raw multicompany {field}",
            )
    for summary in result_body["account_type_summaries"]:
        summary_company_ids = _company_id_list(
            summary["company_ids"],
            permitted=requested,
            label="full-raw multicompany account type summary",
        )
        if summary["company_count"] != len(summary_company_ids):
            raise FullRawEvidenceError(
                "full-raw multicompany account type company count mismatch"
            )
    for line in result_body["account_lines"]:
        if line["company_id"] not in requested:
            raise FullRawEvidenceError(
                "full-raw multicompany account line company scope mismatch"
            )
    gross = result_body["gross_summary"]
    unbalanced = _company_id_list(
        gross["unbalanced_company_ids"],
        permitted=requested,
        label="full-raw multicompany unbalanced companies",
    )
    expected_unbalanced = tuple(
        company["company_id"]
        for company in companies
        if company["ledger_control"]["is_balanced"] is False
    )
    if (
        gross["company_count"] != len(requested)
        or gross["balanced_company_count"]
        != len(requested) - len(expected_unbalanced)
        or unbalanced != expected_unbalanced
    ):
        raise FullRawEvidenceError(
            "full-raw multicompany gross company control mismatch"
        )


def _validate_output_company_binding(
    *,
    capability_id: str,
    result_body: dict[str, Any],
    request: dict[str, Any],
) -> None:
    binding_kind = _OUTPUT_COMPANY_BINDING_KIND.get(capability_id)
    if binding_kind is None:
        raise FullRawEvidenceError(
            "full-raw output company binding policy is missing"
        )
    if binding_kind == "none":
        return
    primary = request["company_id"]
    if binding_kind == "single_filter":
        _require_company(
            result_body["filters"]["company_id"],
            primary,
            "full-raw response filter",
        )
        return
    if binding_kind == "multicurrency":
        _require_company(
            result_body["filters"]["company_id"],
            primary,
            "full-raw multicurrency filter",
        )
        for rate in result_body["rates"]:
            transaction_currency_id = rate["currency_id"]
            company_currency_id = rate["company_currency_id"]
            transaction_source = rate["transaction_technical_source"]
            company_source = rate["company_technical_source"]
            _validate_technical_rate_source(
                transaction_source,
                expected_currency_id=transaction_currency_id,
                allow_no_rate_identity=(
                    transaction_currency_id == company_currency_id
                ),
                label="full-raw multicurrency transaction source",
            )
            _validate_technical_rate_source(
                company_source,
                expected_currency_id=company_currency_id,
                allow_no_rate_identity=True,
                label="full-raw multicurrency company source",
            )
            if (
                transaction_currency_id == company_currency_id
                and not _json_equal(transaction_source, company_source)
            ):
                raise FullRawEvidenceError(
                    "full-raw multicurrency identity source mismatch"
                )
        return
    if binding_kind == "move_eligibility":
        _require_company(
            result_body["filters"]["company_id"],
            primary,
            "full-raw eligibility filter",
        )
        _require_company(
            result_body["target"]["company_id"],
            primary,
            "full-raw eligibility target",
        )
        write_parameters = result_body["write_parameters"]
        if write_parameters is not None:
            _require_company(
                write_parameters["company_id"],
                primary,
                "full-raw eligibility write parameters",
            )
        return
    if binding_kind == "refund_eligibility":
        _require_company(
            result_body["filters"]["company_id"],
            primary,
            "full-raw refund filter",
        )
        for field in ("refund", "origin"):
            _require_company(
                result_body["target"][field]["company_id"],
                primary,
                f"full-raw refund {field}",
            )
        write_parameters = result_body["write_parameters"]
        if write_parameters is not None:
            _require_company(
                write_parameters["company_id"],
                primary,
                "full-raw refund write parameters",
            )
        return
    if binding_kind == "diagnostics":
        _require_company(
            result_body["operation"]["company_id"],
            primary,
            "full-raw diagnostic operation",
        )
        for reference in result_body["odoo_refs"]:
            _require_company(
                reference["company_id"],
                primary,
                "full-raw diagnostic Odoo reference",
            )
        return
    if binding_kind == "multicompany":
        _validate_multicompany_output(result_body, request)
        return
    raise FullRawEvidenceError("full-raw output company binding policy is invalid")


def _validate_receipt(
    value: Any, request: dict[str, Any], response: dict[str, Any]
) -> dict[str, Any]:
    receipt = _exact_fields(value, _RECEIPT_FIELDS, "full-raw receipt")
    for field in (
        "capability_id",
        "capability_channel",
        "database_name",
        "database_uuid",
        "environment",
        "odoo_instance_id",
        "registry_digest",
        "release_digest",
    ):
        if receipt[field] != request[field]:
            raise FullRawEvidenceError(f"full-raw receipt {field} mismatch")
    for field in ("company_id", "user_id"):
        if receipt[field] != request[field]:
            raise FullRawEvidenceError(f"full-raw receipt {field} mismatch")
    _identifier(receipt["id"], "full-raw receipt id")
    _identifier(receipt["signature_key_id"], "full-raw receipt signature_key_id")
    _timestamp(receipt["observed_at"], "full-raw receipt observed_at")
    if receipt["record_count"] != response["record_count"]:
        raise FullRawEvidenceError("full-raw receipt record count mismatch")
    if receipt["request_digest"] != request["request_digest"]:
        raise FullRawEvidenceError("full-raw receipt request binding mismatch")
    if receipt["result_digest"] != response["result_sha256"]:
        raise FullRawEvidenceError("full-raw receipt result binding mismatch")
    if (
        receipt["signature_purpose"] != READ_RECEIPT_PURPOSE
        or receipt["signature_version"] != SIGNATURE_VERSION
    ):
        raise FullRawEvidenceError("full-raw receipt signature contract mismatch")
    _digest(receipt["signature"], "full-raw receipt signature")
    return receipt


def _validate_output_contract(
    *,
    capability: dict[str, Any],
    request: dict[str, Any],
    response: dict[str, Any],
    receipt: dict[str, Any],
) -> None:
    try:
        validate_value(
            {**response["result_body"], "receipt": receipt},
            capability["output_schema"],
        )
    except ContractError as exc:
        raise FullRawEvidenceError(
            "full-raw response does not match the release output schema"
        ) from exc
    _validate_output_company_binding(
        capability_id=capability["id"],
        result_body=response["result_body"],
        request=request,
    )


def _validate_source_witness(
    value: Any,
    *,
    capability_id: str,
    request: dict[str, Any],
    response: dict[str, Any],
    receipt: dict[str, Any],
) -> dict[str, Any]:
    witness = _exact_fields(
        value, _SOURCE_WITNESS_FIELDS, "full-raw source witness"
    )
    expected_source_type = (
        "operation_store"
        if capability_id == "acct.diagnostics.operation_read.v1"
        else "odoo_orm"
    )
    expected_boundary = (
        "snapshot_comparison"
        if expected_source_type == "operation_store"
        else "transaction_rollback"
    )
    if (
        witness["source_type"] != expected_source_type
        or witness["boundary_mode"] != expected_boundary
        or witness["read_only"] is not True
        or witness["rolled_back"] is not (expected_boundary == "transaction_rollback")
    ):
        raise FullRawEvidenceError("full-raw source witness boundary mismatch")
    for field in ("odoo_write_count", "write_statement_count"):
        if _nonnegative_integer(witness[field], f"source witness {field}") != 0:
            raise FullRawEvidenceError("full-raw source witness observed a write")
    for field in (
        "post_state_sha256",
        "pre_state_sha256",
        "receipt_sha256",
        "request_sha256",
        "response_sha256",
    ):
        _digest(witness[field], f"source witness {field}")
    if witness["pre_state_sha256"] != witness["post_state_sha256"]:
        raise FullRawEvidenceError("full-raw source witness state changed")
    expected = {
        "request_sha256": _json_digest(request),
        "response_sha256": _json_digest(response),
        "receipt_sha256": _json_digest(receipt),
    }
    if any(witness[field] != digest for field, digest in expected.items()):
        raise FullRawEvidenceError("full-raw source witness raw binding mismatch")
    return witness


def _validate_execution(
    value: Any,
    *,
    capability_id: str,
    capability: dict[str, Any],
    contract: str,
    scope: dict[str, Any],
    scope_sha256: str,
    identity: dict[str, Any],
    run_id: str,
) -> dict[str, Any]:
    execution = _exact_fields(value, _EXECUTION_FIELDS, "full-raw execution")
    request = _validate_request(
        execution["request"],
        capability_id=capability_id,
        capability=capability,
        contract=contract,
        scope=scope,
        scope_sha256=scope_sha256,
        identity=identity,
        run_id=run_id,
    )
    response = _validate_response(execution["response"], request)
    receipt = _validate_receipt(execution["receipt"], request, response)
    _validate_output_contract(
        capability=capability,
        request=request,
        response=response,
        receipt=receipt,
    )
    _validate_source_witness(
        execution["source_witness"],
        capability_id=capability_id,
        request=request,
        response=response,
        receipt=receipt,
    )
    return execution


def _validate_live_cases(
    cases: list[Any], **context: Any
) -> None:
    if len(cases) != 1:
        raise FullRawEvidenceError("live Odoo evidence requires exactly one case")
    case = _exact_fields(cases[0], _LIVE_CASE_FIELDS, "live Odoo case")
    _identifier(case["case_id"], "live Odoo case_id")
    _validate_execution(case["execution"], **context)


def _allowed_oracle_types(capability_id: str) -> frozenset[str]:
    if capability_id == "acct.registry.list.v1":
        return frozenset({"registry_contract"})
    if capability_id == "acct.diagnostics.operation_read.v1":
        return frozenset({"durable_store"})
    if "eligibility" in capability_id:
        return frozenset({"business_rule"})
    return frozenset({"postgresql_sql", "business_rule"})


def _validate_oracle_definition(
    value: Any, *, capability_id: str, identity: dict[str, Any]
) -> tuple[dict[str, Any], str]:
    definition = _object(value, "accounting oracle definition")
    oracle_type = definition.get("oracle_type")
    if (
        type(oracle_type) is not str
        or oracle_type not in _ORACLE_DEFINITION_FIELDS
        or oracle_type not in _allowed_oracle_types(capability_id)
    ):
        raise FullRawEvidenceError("accounting oracle type is invalid for capability")
    definition = _exact_fields(
        definition,
        _ORACLE_DEFINITION_FIELDS[oracle_type],
        "accounting oracle definition",
    )
    _identifier(definition["oracle_id"], "accounting oracle id")
    _digest(definition["oracle_code_sha256"], "accounting oracle code digest")
    if oracle_type == "postgresql_sql":
        query = _bounded_text(
            definition["query_text"],
            "accounting oracle query",
            maximum=MAX_QUERY_BYTES,
            multiline=True,
        )
        if definition["statement_type"] != "select":
            raise FullRawEvidenceError("accounting oracle SQL must be typed select")
        if type(definition["query_parameters"]) is not dict:
            raise FullRawEvidenceError("accounting oracle query parameters are invalid")
        if definition["query_sha256"] != _json_digest(query):
            raise FullRawEvidenceError("accounting oracle query digest mismatch")
    elif oracle_type == "business_rule":
        if type(definition["rule_inputs"]) is not dict:
            raise FullRawEvidenceError("accounting oracle rule inputs are invalid")
        if definition["rule_inputs_sha256"] != _json_digest(
            definition["rule_inputs"]
        ):
            raise FullRawEvidenceError("accounting oracle rule input digest mismatch")
        _digest(definition["ruleset_sha256"], "accounting oracle ruleset digest")
    elif oracle_type == "registry_contract":
        if definition["registry_digest"] != identity["registry_digest"]:
            raise FullRawEvidenceError("accounting oracle registry digest mismatch")
        _digest(
            definition["registry_schema_sha256"],
            "accounting oracle registry schema digest",
        )
    else:
        _digest(
            definition["store_schema_sha256"],
            "accounting oracle store schema digest",
        )
        _digest(
            definition["store_snapshot_sha256"],
            "accounting oracle store snapshot digest",
        )
    return definition, oracle_type


def _validate_oracle_company_binding(
    definition: dict[str, Any],
    *,
    oracle_type: str,
    capability_id: str,
    capability: dict[str, Any],
    request: dict[str, Any],
) -> None:
    requested = _requested_company_ids(request, capability)
    if oracle_type == "postgresql_sql":
        query_parameters = definition["query_parameters"]
        if not _json_equal(query_parameters, request["parameters"]):
            raise FullRawEvidenceError(
                "accounting oracle query parameters do not exactly match the request"
            )
        if capability_id == "acct.multicompany.consolidated_read.v1":
            _company_id_list(
                query_parameters.get("company_ids"),
                permitted=requested,
                label="accounting oracle query parameters",
                exact=True,
            )
        else:
            _require_company(
                query_parameters.get("company_id"),
                request["company_id"],
                "accounting oracle query parameters",
            )
    elif oracle_type == "business_rule":
        rule_inputs = definition["rule_inputs"]
        if not _json_equal(rule_inputs, request["parameters"]):
            raise FullRawEvidenceError(
                "accounting oracle rule inputs do not exactly match the request"
            )
        if capability_id == "acct.multicompany.consolidated_read.v1":
            _company_id_list(
                rule_inputs.get("company_ids"),
                permitted=requested,
                label="accounting oracle rule inputs",
                exact=True,
            )
        else:
            _require_company(
                rule_inputs.get("company_id"),
                request["company_id"],
                "accounting oracle rule inputs",
            )


def _validate_oracle_source_companies(
    source_records: list[dict[str, Any]],
    *,
    capability_id: str,
    capability: dict[str, Any],
    request: dict[str, Any],
) -> None:
    requested = _requested_company_ids(request, capability)
    for record in source_records:
        company_id = record.get("company_id")
        if type(company_id) is not int or company_id not in requested:
            raise FullRawEvidenceError(
                "accounting oracle source record company binding mismatch"
            )
        for field, field_value in record.items():
            if (
                capability_id in _ORACLE_TECHNICAL_COMPANY_CAPABILITIES
                and field in _ORACLE_TECHNICAL_COMPANY_FIELDS
            ):
                if field_value is not None:
                    _positive_integer(
                        field_value,
                        f"accounting oracle source record {field}",
                    )
            elif field != "company_id" and field.endswith("_company_id"):
                if type(field_value) is not int or field_value not in requested:
                    raise FullRawEvidenceError(
                        "accounting oracle source record company scope mismatch"
                    )
            elif field == "company_ids" or field.endswith("_company_ids"):
                _company_id_list(
                    field_value,
                    permitted=requested,
                    label="accounting oracle source record",
                )
        technical_fields = _ORACLE_TECHNICAL_COMPANY_FIELDS.intersection(record)
        if (
            capability_id in _ORACLE_TECHNICAL_COMPANY_CAPABILITIES
            and technical_fields
            and "source_scope" in record
        ):
            source_scope = record["source_scope"]
            source_company_id = record.get("source_company_id")
            rate_company_id = record.get("rate_company_id")
            if source_scope == "company_specific":
                source_company_id = _positive_integer(
                    source_company_id,
                    "accounting oracle technical source_company_id",
                )
                if (
                    rate_company_id is not None
                    and source_company_id != rate_company_id
                ):
                    raise FullRawEvidenceError(
                        "accounting oracle technical rate company mismatch"
                    )
            elif source_scope in {"global", "no_rate_identity"}:
                if source_company_id is not None:
                    raise FullRawEvidenceError(
                        "accounting oracle technical source scope mismatch"
                    )
            else:
                raise FullRawEvidenceError(
                    "accounting oracle technical source scope is invalid"
                )


def _validate_oracle_cases(cases: list[Any], **context: Any) -> None:
    if len(cases) != 1:
        raise FullRawEvidenceError("accounting oracle requires exactly one case")
    capability_id = context["capability_id"]
    case = _exact_fields(
        cases[0], _ORACLE_CASE_FIELDS, "accounting oracle case"
    )
    _identifier(case["case_id"], "accounting oracle case_id")
    execution = _validate_execution(case["execution"], **context)
    definition, oracle_type = _validate_oracle_definition(
        case["oracle_definition"],
        capability_id=capability_id,
        identity=context["identity"],
    )
    _validate_oracle_company_binding(
        definition,
        oracle_type=oracle_type,
        capability_id=capability_id,
        capability=context["capability"],
        request=execution["request"],
    )
    source_records = case["source_records"]
    if (
        type(source_records) is not list
        or len(source_records) > MAX_SOURCE_RECORDS
        or any(type(record) is not dict for record in source_records)
    ):
        raise FullRawEvidenceError("accounting oracle source records are invalid")
    _validate_oracle_source_companies(
        source_records,
        capability_id=capability_id,
        capability=context["capability"],
        request=execution["request"],
    )
    source_digest = _json_digest(source_records)
    if case["source_records_sha256"] != source_digest:
        raise FullRawEvidenceError("accounting oracle source records digest mismatch")
    oracle_result = case["oracle_result"]
    if type(oracle_result) is not dict:
        raise FullRawEvidenceError("accounting oracle result must be an object")
    oracle_result_digest = _json_digest(oracle_result)
    if case["oracle_result_sha256"] != oracle_result_digest:
        raise FullRawEvidenceError("accounting oracle result digest mismatch")
    observed_result = execution["response"]["result_body"]
    if not _json_equal(oracle_result, observed_result):
        raise FullRawEvidenceError(
            "accounting oracle result does not exactly match observed result"
        )
    witness = _exact_fields(
        case["oracle_witness"],
        _ORACLE_WITNESS_FIELDS,
        "accounting oracle witness",
    )
    expected_boundary = (
        "transaction_rollback"
        if oracle_type == "postgresql_sql"
        else "snapshot_comparison"
    )
    if (
        witness["oracle_type"] != oracle_type
        or witness["boundary_mode"] != expected_boundary
        or witness["read_only"] is not True
        or witness["rolled_back"] is not (oracle_type == "postgresql_sql")
        or _nonnegative_integer(witness["write_count"], "oracle write_count") != 0
    ):
        raise FullRawEvidenceError("accounting oracle witness boundary is invalid")
    _timestamp(witness["executed_at"], "accounting oracle executed_at")
    for field in (
        "observed_result_sha256",
        "oracle_definition_sha256",
        "oracle_input_sha256",
        "oracle_result_sha256",
        "post_state_sha256",
        "pre_state_sha256",
        "source_records_sha256",
    ):
        _digest(witness[field], f"accounting oracle witness {field}")
    source_record_count = _nonnegative_integer(
        witness["source_record_count"],
        "accounting oracle source_record_count",
    )
    expected_input = {
        "oracle_definition": definition,
        "parameters": execution["request"]["parameters"],
        "source_records": source_records,
    }
    if witness["pre_state_sha256"] != witness["post_state_sha256"]:
        raise FullRawEvidenceError("accounting oracle witness state changed")
    if (
        witness["source_records_sha256"] != source_digest
        or source_record_count != len(source_records)
    ):
        raise FullRawEvidenceError(
            "accounting oracle witness source records binding mismatch"
        )
    if (
        witness["oracle_definition_sha256"] != _json_digest(definition)
        or witness["oracle_input_sha256"] != _json_digest(expected_input)
        or witness["oracle_result_sha256"] != oracle_result_digest
        or witness["observed_result_sha256"]
        != execution["response"]["result_sha256"]
    ):
        raise FullRawEvidenceError("accounting oracle witness binding mismatch")


def _validate_security_request(
    value: Any, **context: Any
) -> dict[str, Any]:
    return _validate_request(
        value, allow_company_binding_failure=True, **context
    )


def _validate_security_cases(cases: list[Any], **context: Any) -> None:
    if len(cases) != len(SECURITY_CASES):
        raise FullRawEvidenceError("security evidence must contain five cases")
    request_digests: set[str] = set()
    response_digests: set[str] = set()
    for raw_case, (case_id, error_code) in zip(cases, SECURITY_CASES, strict=True):
        case = _exact_fields(
            raw_case, _SECURITY_CASE_FIELDS, "security negative case"
        )
        if case["case_id"] != case_id:
            raise FullRawEvidenceError("security cases are out of order")
        if case["expected_error_code"] != error_code:
            raise FullRawEvidenceError("security expected error code mismatch")
        if _positive_integer(case["exit_code"], "security exit_code") != 6:
            raise FullRawEvidenceError("security exit_code must be 6")
        request = _validate_security_request(case["request"], **context)
        request_sha256 = _json_digest(request)
        if case["request_sha256"] != request_sha256:
            raise FullRawEvidenceError("security request digest mismatch")
        response = _exact_fields(
            case["response"], _SECURITY_RESPONSE_FIELDS, "security response"
        )
        if (
            response["request_id"] != request["request_id"]
            or response["status"] != "error"
            or response["error_code"] != error_code
            or response["result"] is not None
            or response["receipt"] is not None
        ):
            raise FullRawEvidenceError("security observed error code/response mismatch")
        _bounded_text(
            response["error_message"],
            "security error message",
            maximum=MAX_TEXT_BYTES,
            multiline=True,
        )
        response_sha256 = _json_digest(response)
        if case["response_sha256"] != response_sha256:
            raise FullRawEvidenceError("security response digest mismatch")
        if (
            request_sha256 in request_digests
            or response_sha256 in response_digests
            or request_sha256 == response_sha256
        ):
            raise FullRawEvidenceError("security request/response evidence is not unique")
        request_digests.add(request_sha256)
        response_digests.add(response_sha256)
        auth = _exact_fields(
            case["auth_witness"], _AUTH_WITNESS_FIELDS, "security auth witness"
        )
        _digest(
            auth["bound_parameters_sha256"],
            "security bound_parameters_sha256",
        )
        _, not_before = _timestamp(auth["not_before"], "security not_before")
        _, expires_at = _timestamp(auth["expires_at"], "security expires_at")
        _, observed_at = _timestamp(auth["observed_at"], "security observed_at")
        if not_before >= expires_at:
            raise FullRawEvidenceError("security token validity window is invalid")
        attempt_count = _positive_integer(
            auth["attempt_count"], "security attempt_count"
        )
        if type(auth["odoo_permission_granted"]) is not bool:
            raise FullRawEvidenceError("security ACL witness is invalid")
        if case_id == "acl_deny":
            if auth["odoo_permission_granted"] is not False:
                raise FullRawEvidenceError("security ACL denial was not witnessed")
        elif auth["odoo_permission_granted"] is not True:
            raise FullRawEvidenceError("security permission witness is inconsistent")
        if case_id == "cross_company":
            if request["company_id"] in request["allowed_company_ids"]:
                raise FullRawEvidenceError("security cross-company attack is not present")
        elif request["company_id"] not in request["allowed_company_ids"]:
            raise FullRawEvidenceError("security company witness is inconsistent")
        if case_id == "expired":
            if observed_at < expires_at:
                raise FullRawEvidenceError("security expired token was not expired")
        elif not (not_before <= observed_at < expires_at):
            raise FullRawEvidenceError("security token time witness is inconsistent")
        if case_id == "replay":
            if attempt_count < 2:
                raise FullRawEvidenceError("security replay attempt was not witnessed")
        elif attempt_count != 1:
            raise FullRawEvidenceError("security attempt witness is inconsistent")
        if case_id == "tamper_parameters":
            if auth["bound_parameters_sha256"] == request["parameters_sha256"]:
                raise FullRawEvidenceError("security parameter tampering is not present")
        elif auth["bound_parameters_sha256"] != request["parameters_sha256"]:
            raise FullRawEvidenceError("security parameter binding is inconsistent")
        side_effects = _exact_fields(
            case["side_effect_witness"],
            _SIDE_EFFECT_FIELDS,
            "security side-effect witness",
        )
        for field in (
            "cli_business_write_count",
            "odoo_write_count",
            "postgresql_write_count",
            "receipt_count",
            "result_count",
        ):
            if _nonnegative_integer(side_effects[field], f"security {field}") != 0:
                raise FullRawEvidenceError("security side effects were observed")
        for field in (
            "business_state_post_sha256",
            "business_state_pre_sha256",
        ):
            _digest(side_effects[field], f"security {field}")
        if (
            side_effects["business_state_pre_sha256"]
            != side_effects["business_state_post_sha256"]
        ):
            raise FullRawEvidenceError("security side effects changed business state")


def _validate_release_cases(cases: list[Any], **context: Any) -> None:
    if len(cases) != 1:
        raise FullRawEvidenceError("release identity requires exactly one case")
    case = _exact_fields(
        cases[0], _RELEASE_CASE_FIELDS, "release identity case"
    )
    if case["case_id"] != "release-identity":
        raise FullRawEvidenceError("release identity case_id is invalid")
    if case["capability_contract_sha256"] != context["contract"]:
        raise FullRawEvidenceError("release identity contract mismatch")
    if case["scope_sha256"] != context["scope_sha256"]:
        raise FullRawEvidenceError("release identity scope mismatch")
    identity = _validate_release_identity(
        case["observed_release_identity"], "observed release identity"
    )
    if not _json_equal(identity, context["identity"]):
        raise FullRawEvidenceError("observed release identity mismatch")
    if case["release_identity_sha256"] != _json_digest(identity):
        raise FullRawEvidenceError("release identity digest mismatch")


def validate_full_raw_evidence(
    document: Mapping[str, Any],
    *,
    expected_registry: tuple[Capability, ...],
    expected_scope: Mapping[str, Any],
    expected_scope_sha256: str,
    expected_release_identity: Mapping[str, Any],
    expected_run_id: str,
) -> dict[str, Any]:
    """Validate one full-raw evidence document without asserting source trust.

    All ``expected_*`` values are inputs already authenticated by the caller.
    A successful result proves exact fields, types, ordering, bounds, and
    internal content bindings.  It deliberately leaves source trust, external
    evidence, and Goal admission false until a separate trusted producer and
    attestor are implemented.
    """

    raw_document = _object(document, "full-raw document")
    node_count, raw_size = _measure_document(raw_document)
    contracts, read_capabilities, scope, identity = _validate_expected_context(
        expected_registry=expected_registry,
        expected_scope=expected_scope,
        expected_scope_sha256=expected_scope_sha256,
        expected_release_identity=expected_release_identity,
        expected_run_id=expected_run_id,
    )
    raw_document = _exact_fields(raw_document, _ROOT_FIELDS, "full-raw document")
    if raw_document["schema_version"] != FULL_RAW_EVIDENCE_SCHEMA:
        raise FullRawEvidenceError("full-raw schema is invalid")
    evidence_kind = raw_document["evidence_kind"]
    if evidence_kind == "pi_e2e":
        raise FullRawEvidenceError(PI_TRUSTED_VERIFIER_BLOCKER)
    if evidence_kind not in EVIDENCE_KINDS:
        raise FullRawEvidenceError("full-raw evidence kind is invalid")
    if raw_document["run_id"] != expected_run_id:
        raise FullRawEvidenceError("full-raw run_id mismatch")
    if raw_document["scope_sha256"] != expected_scope_sha256:
        raise FullRawEvidenceError("full-raw scope mismatch")
    observed_identity = _validate_release_identity(
        raw_document["release_identity"], "full-raw release identity"
    )
    if not _json_equal(observed_identity, identity):
        raise FullRawEvidenceError("full-raw release identity mismatch")
    capabilities = raw_document["capabilities"]
    if (
        type(capabilities) is not list
        or not capabilities
        or len(capabilities) > MAX_CAPABILITIES
    ):
        raise FullRawEvidenceError("full-raw capability list is invalid")
    capability_ids = [
        item.get("capability_id") if type(item) is dict else None
        for item in capabilities
    ]
    if any(
        type(capability_id) is not str
        or _CAPABILITY_ID.fullmatch(capability_id) is None
        for capability_id in capability_ids
    ):
        raise FullRawEvidenceError("full-raw capability ID is invalid")
    if capability_ids != sorted(capability_ids):
        raise FullRawEvidenceError("full-raw capabilities must be sorted and unique")
    if tuple(capability_ids) != tuple(sorted(contracts)):
        raise FullRawEvidenceError("full-raw capability coverage mismatch")
    validators = {
        "accounting_oracle": _validate_oracle_cases,
        "live_odoo": _validate_live_cases,
        "release_identity": _validate_release_cases,
        "security_negative": _validate_security_cases,
    }
    summaries: list[dict[str, Any]] = []
    total_cases = 0
    for raw_capability in capabilities:
        capability = _exact_fields(
            raw_capability, _CAPABILITY_FIELDS, "full-raw capability"
        )
        capability_id = capability["capability_id"]
        contract = capability["capability_contract_sha256"]
        if contract != contracts[capability_id]:
            raise FullRawEvidenceError("full-raw capability contract mismatch")
        cases = capability["cases"]
        if (
            type(cases) is not list
            or not cases
            or len(cases) > MAX_CASES_PER_CAPABILITY
        ):
            raise FullRawEvidenceError("full-raw capability cases are invalid")
        context = {
            "capability_id": capability_id,
            "capability": read_capabilities[capability_id],
            "contract": contract,
            "scope": scope,
            "scope_sha256": expected_scope_sha256,
            "identity": identity,
            "run_id": expected_run_id,
        }
        validators[evidence_kind](cases, **context)
        total_cases += len(cases)
        summaries.append(
            {
                "capability_contract_sha256": contract,
                "capability_id": capability_id,
                "case_count": len(cases),
                "cases_sha256": _json_digest(cases),
            }
        )
    blockers = [TRUSTED_SOURCE_ADAPTER_BLOCKER]
    if evidence_kind == "accounting_oracle":
        blockers.append(ORACLE_READ_ONLY_ATTESTATION_BLOCKER)
    return {
        "blockers": blockers,
        "capabilities": summaries,
        "capability_count": len(capabilities),
        "case_count": total_cases,
        "evidence_kind": evidence_kind,
        "external_read_evidence_verified": False,
        "full_raw_contract_validated": True,
        "goal_evidence_admissible": False,
        "oracle_execution_attested": False,
        "production_promotion_allowed": False,
        "receipt_signatures_verified": False,
        "raw_node_count": node_count,
        "raw_sha256": _json_digest(raw_document),
        "raw_size_bytes": raw_size,
        "release_identity_binding_validated": True,
        "run_id": expected_run_id,
        "schema_version": FULL_RAW_VALIDATION_REPORT_SCHEMA,
        "scope_sha256": expected_scope_sha256,
        "trusted_source_observed": False,
    }
