from __future__ import annotations

import hashlib
import inspect
import json
import re
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

import odoo_accounting_cli_v3.read_evidence_raw_v3 as raw_v3
from odoo_accounting_cli_v3.contracts import validate_value
from odoo_accounting_cli_v3.receipts import read_request_digest
from odoo_accounting_cli_v3.registry import load_registry, registry_digest


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


REGISTRY = load_registry(
    Path(__file__).resolve().parents[1] / "registry" / "capabilities.json"
)
READ_CAPABILITIES = {
    capability.id: capability
    for capability in REGISTRY
    if capability.data["access"] == "read"
}
CAPABILITY_IDS = tuple(sorted(READ_CAPABILITIES))
CONTRACTS = {
    capability_id: _digest(READ_CAPABILITIES[capability_id].data)
    for capability_id in CAPABILITY_IDS
}
IDENTITY = {
    "commit": "1" * 40,
    "manifest_sha256": "2" * 64,
    "package_sha256": "3" * 64,
    "registry_digest": registry_digest(REGISTRY),
    "release": "odoo-accounting-cli-v3-0.1.0.dev264-111111111111",
    "verified": True,
    "version": "0.1.0.dev264",
}
RUN_ID = "run-20260810-000001"
SCOPE = {
    "capability_contracts": deepcopy(CONTRACTS),
    "company_ids": [1, 2],
    "database_name": "odoo_test",
    "database_uuid": "11111111-2222-4333-8444-555555555555",
    "environment": "test",
    "release_identity": deepcopy(IDENTITY),
    "run_id": RUN_ID,
    "schema_version": "odoo-accounting-cli-v3.read-evidence-scope.v3",
}
SCOPE_SHA256 = hashlib.sha256(
    (
        json.dumps(
            SCOPE,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")
).hexdigest()
NOW = "2026-08-10T08:00:00Z"

SECURITY_CASES = (
    ("acl_deny", "odoo_acl_denied"),
    ("cross_company", "company_binding_rejected"),
    ("expired", "authentication_expired"),
    ("replay", "authentication_replayed"),
    ("tamper_parameters", "authentication_tampered"),
)
def _schema_string(schema: dict[str, Any], *, index: int = 0) -> str:
    if "enum" in schema:
        return str(schema["enum"][index % len(schema["enum"])])
    minimum = schema.get("minLength", 0)
    maximum = schema.get("maxLength", 4096)
    pattern = schema.get("pattern")
    candidates = (
        "",
        "x",
        "1",
        "1.0",
        "0",
        "acct.test.read.v1",
        "operation-1",
        "period-" + "0" * 64,
        "0" * 64,
        SCOPE["database_uuid"] if "SCOPE" in globals() else "11111111-2222-4333-8444-555555555555",
        "2026-07-31",
        NOW if "NOW" in globals() else "2026-08-10T08:00:00Z",
    )
    if schema.get("format") == "date":
        return "2026-07-31"
    if schema.get("format") == "date-time":
        return NOW
    for candidate in candidates:
        if not minimum <= len(candidate) <= maximum:
            continue
        if pattern is None or re.fullmatch(pattern, candidate) is not None:
            return candidate
    candidate = "x" * max(1, minimum)
    if len(candidate) <= maximum and (
        pattern is None or re.fullmatch(pattern, candidate) is not None
    ):
        return candidate
    raise AssertionError(f"no deterministic fixture for string schema: {schema}")


def _schema_value(schema: dict[str, Any], *, index: int = 0) -> Any:
    if "oneOf" in schema:
        return _schema_value(schema["oneOf"][0], index=index)
    if "enum" in schema:
        return deepcopy(schema["enum"][index % len(schema["enum"])])
    kind = schema.get("type")
    if type(kind) is list:
        selected = next(item for item in kind if item != "null")
        return _schema_value({**schema, "type": selected}, index=index)
    if kind == "object":
        properties = schema.get("properties", {})
        return {
            field: _schema_value(properties[field])
            for field in schema.get("required", [])
        }
    if kind == "array":
        count = schema.get("minItems", 0)
        return [
            _schema_value(schema["items"], index=item_index)
            for item_index in range(count)
        ]
    if kind == "string":
        return _schema_string(schema, index=index)
    if kind == "integer":
        return int(schema.get("minimum", 0)) + index
    if kind == "number":
        return schema.get("minimum", 0)
    if kind == "boolean":
        return False
    if kind == "null":
        return None
    raise AssertionError(f"unsupported fixture schema: {schema}")


def _parameters(capability_id: str) -> dict[str, Any]:
    return _schema_value(READ_CAPABILITIES[capability_id].data["input_schema"])


def _result_body(capability_id: str) -> dict[str, Any]:
    result = _schema_value(
        READ_CAPABILITIES[capability_id].data["output_schema"]
    )
    assert type(result) is dict
    result.pop("receipt")
    if capability_id == "acct.multicompany.consolidated_read.v1":
        companies = result["companies"]
        unbalanced_company_ids = [
            company["company_id"]
            for company in companies
            if company["ledger_control"]["is_balanced"] is False
        ]
        result["gross_summary"]["unbalanced_company_ids"] = (
            unbalanced_company_ids
        )
        result["gross_summary"]["balanced_company_count"] = (
            len(companies) - len(unbalanced_company_ids)
        )
    if capability_id == "acct.multicurrency.balance_read.v1":
        for rate in result["rates"]:
            for field in (
                "transaction_technical_source",
                "company_technical_source",
            ):
                source = rate[field]
                if source["source_scope"] == "no_rate_identity":
                    source["effective_date"] = None
                    source["source_company_id"] = None
                    source["source_record_id"] = None
    return result


def _request(
    capability_id: str,
    *,
    company_id: int = 1,
    allowed_company_ids: list[int] | None = None,
    parameters: dict[str, Any] | None = None,
) -> dict[str, Any]:
    request_parameters = deepcopy(parameters or _parameters(capability_id))
    if parameters is None and "company_id" in request_parameters:
        request_parameters["company_id"] = company_id
    allowed = list(allowed_company_ids or [1, 2])
    request = {
        "allowed_company_ids": allowed,
        "auth_token_id": f"auth-{hashlib.sha256(capability_id.encode()).hexdigest()[:16]}",
        "capability_channel": "staged",
        "capability_contract_sha256": CONTRACTS[capability_id],
        "capability_id": capability_id,
        "company_id": company_id,
        "database_name": SCOPE["database_name"],
        "database_uuid": SCOPE["database_uuid"],
        "environment": SCOPE["environment"],
        "odoo_instance_id": "odoo-test-instance",
        "parameters": request_parameters,
        "parameters_sha256": _digest(request_parameters),
        "principal": "pi-accountant-test",
        "registry_digest": IDENTITY["registry_digest"],
        "release_digest": IDENTITY["manifest_sha256"],
        "release_identity_sha256": _digest(IDENTITY),
        "request_id": f"request-{hashlib.sha256((capability_id + str(company_id)).encode()).hexdigest()[:16]}",
        "run_id": RUN_ID,
        "scope_sha256": SCOPE_SHA256,
        "user_id": 7,
    }
    request["request_digest"] = read_request_digest(
        capability_id=capability_id,
        parameters=request_parameters,
        auth_token_id=request["auth_token_id"],
        principal=request["principal"],
        odoo_instance_id=request["odoo_instance_id"],
        database_name=request["database_name"],
        database_uuid=request["database_uuid"],
        company_id=company_id,
        user_id=request["user_id"],
        registry_digest=request["registry_digest"],
        release_digest=request["release_digest"],
        environment=request["environment"],
        capability_channel=request["capability_channel"],
    )
    return request


def _response(request: dict[str, Any]) -> dict[str, Any]:
    result_body = _result_body(request["capability_id"])
    record_count = result_body["page"]["total_count"]
    return {
        "record_count": record_count,
        "request_id": request["request_id"],
        "result_body": result_body,
        "result_sha256": _digest(result_body),
        "status": "ok",
    }


def _receipt(request: dict[str, Any], response: dict[str, Any]) -> dict[str, Any]:
    return {
        "capability_channel": request["capability_channel"],
        "capability_id": request["capability_id"],
        "company_id": request["company_id"],
        "database_name": request["database_name"],
        "database_uuid": request["database_uuid"],
        "environment": request["environment"],
        "id": f"receipt-{hashlib.sha256(request['request_id'].encode()).hexdigest()[:16]}",
        "observed_at": NOW,
        "odoo_instance_id": request["odoo_instance_id"],
        "record_count": response["record_count"],
        "registry_digest": request["registry_digest"],
        "release_digest": request["release_digest"],
        "request_digest": request["request_digest"],
        "result_digest": response["result_sha256"],
        "signature": "5" * 64,
        "signature_key_id": "sandbox-read-receipt-v1",
        "signature_purpose": "read_receipt_v2",
        "signature_version": 2,
        "user_id": request["user_id"],
    }


def _execution(capability_id: str) -> dict[str, Any]:
    request = _request(capability_id)
    response = _response(request)
    receipt = _receipt(request, response)
    state = _digest({"capability_id": capability_id, "state": "unchanged"})
    source_type = (
        "operation_store"
        if capability_id == "acct.diagnostics.operation_read.v1"
        else "odoo_orm"
    )
    boundary_mode = (
        "snapshot_comparison"
        if source_type == "operation_store"
        else "transaction_rollback"
    )
    return {
        "receipt": receipt,
        "request": request,
        "response": response,
        "source_witness": {
            "boundary_mode": boundary_mode,
            "odoo_write_count": 0,
            "post_state_sha256": state,
            "pre_state_sha256": state,
            "read_only": True,
            "receipt_sha256": _digest(receipt),
            "request_sha256": _digest(request),
            "response_sha256": _digest(response),
            "rolled_back": boundary_mode == "transaction_rollback",
            "source_type": source_type,
            "write_statement_count": 0,
        },
    }


def _rebind_request(execution: dict[str, Any]) -> None:
    request = execution["request"]
    request["parameters_sha256"] = _digest(request["parameters"])
    request["request_digest"] = read_request_digest(
        capability_id=request["capability_id"],
        parameters=request["parameters"],
        auth_token_id=request["auth_token_id"],
        principal=request["principal"],
        odoo_instance_id=request["odoo_instance_id"],
        database_name=request["database_name"],
        database_uuid=request["database_uuid"],
        company_id=request["company_id"],
        user_id=request["user_id"],
        registry_digest=request["registry_digest"],
        release_digest=request["release_digest"],
        environment=request["environment"],
        capability_channel=request["capability_channel"],
    )
    receipt = execution["receipt"]
    receipt["request_digest"] = request["request_digest"]
    execution["source_witness"]["request_sha256"] = _digest(request)
    execution["source_witness"]["receipt_sha256"] = _digest(receipt)


def _rebind_response(execution: dict[str, Any]) -> None:
    response = execution["response"]
    response["result_sha256"] = _digest(response["result_body"])
    receipt = execution["receipt"]
    receipt["record_count"] = response["record_count"]
    receipt["result_digest"] = response["result_sha256"]
    execution["source_witness"]["response_sha256"] = _digest(response)
    execution["source_witness"]["receipt_sha256"] = _digest(receipt)


def _live_case(capability_id: str) -> dict[str, Any]:
    return {"case_id": "live-primary", "execution": _execution(capability_id)}


def _oracle_type(capability_id: str) -> str:
    if capability_id == "acct.registry.list.v1":
        return "registry_contract"
    if capability_id == "acct.diagnostics.operation_read.v1":
        return "durable_store"
    if "eligibility" in capability_id:
        return "business_rule"
    return "postgresql_sql"


def _oracle_definition(
    capability_id: str, parameters: dict[str, Any]
) -> dict[str, Any]:
    oracle_type = _oracle_type(capability_id)
    common = {
        "oracle_code_sha256": _digest({"oracle": capability_id}),
        "oracle_id": f"oracle-{hashlib.sha256(capability_id.encode()).hexdigest()[:16]}",
        "oracle_type": oracle_type,
    }
    if oracle_type == "postgresql_sql":
        if capability_id == "acct.multicompany.consolidated_read.v1":
            query_text = (
                "SELECT company_id, balance FROM account_move_line "
                "WHERE company_id = ANY(%(company_ids)s)"
            )
        else:
            query_text = (
                "SELECT company_id, balance FROM account_move_line "
                "WHERE company_id = %(company_id)s"
            )
        return {
            **common,
            "query_parameters": deepcopy(parameters),
            "query_sha256": _digest(query_text),
            "query_text": query_text,
            "statement_type": "select",
        }
    if oracle_type == "business_rule":
        rule_inputs = deepcopy(parameters)
        return {
            **common,
            "rule_inputs": rule_inputs,
            "rule_inputs_sha256": _digest(rule_inputs),
            "ruleset_sha256": _digest({"ruleset": capability_id}),
        }
    if oracle_type == "registry_contract":
        return {
            **common,
            "registry_digest": IDENTITY["registry_digest"],
            "registry_schema_sha256": _digest({"schema": "registry-v3"}),
        }
    return {
        **common,
        "store_schema_sha256": _digest({"schema": "operation-store-v1"}),
        "store_snapshot_sha256": _digest({"snapshot": capability_id}),
    }


def _oracle_case(capability_id: str) -> dict[str, Any]:
    execution = _execution(capability_id)
    oracle_definition = _oracle_definition(
        capability_id, execution["request"]["parameters"]
    )
    source_records = [{"company_id": 1, "source": capability_id, "value": "100.00"}]
    source_records_sha256 = _digest(source_records)
    oracle_result = deepcopy(execution["response"]["result_body"])
    oracle_result_sha256 = _digest(oracle_result)
    oracle_type = _oracle_type(capability_id)
    state = _digest({"oracle": capability_id, "state": "unchanged"})
    return {
        "case_id": "oracle-primary",
        "execution": execution,
        "oracle_definition": oracle_definition,
        "oracle_result": oracle_result,
        "oracle_result_sha256": oracle_result_sha256,
        "oracle_witness": {
            "boundary_mode": (
                "transaction_rollback"
                if oracle_type == "postgresql_sql"
                else "snapshot_comparison"
            ),
            "executed_at": NOW,
            "observed_result_sha256": execution["response"]["result_sha256"],
            "oracle_definition_sha256": _digest(oracle_definition),
            "oracle_input_sha256": _digest(
                {
                    "oracle_definition": oracle_definition,
                    "parameters": execution["request"]["parameters"],
                    "source_records": source_records,
                }
            ),
            "oracle_result_sha256": oracle_result_sha256,
            "oracle_type": oracle_type,
            "post_state_sha256": state,
            "pre_state_sha256": state,
            "read_only": True,
            "rolled_back": oracle_type == "postgresql_sql",
            "source_record_count": len(source_records),
            "source_records_sha256": source_records_sha256,
            "write_count": 0,
        },
        "source_records": source_records,
        "source_records_sha256": source_records_sha256,
    }


def _security_request(
    capability_id: str, case_id: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    request = _request(capability_id)
    if case_id == "cross_company":
        request = _request(capability_id, company_id=2, allowed_company_ids=[1])
    request["auth_token_id"] = f"{request['auth_token_id']}-{case_id}"
    request["request_id"] = f"{request['request_id']}-{case_id}"
    request["request_digest"] = read_request_digest(
        capability_id=request["capability_id"],
        parameters=request["parameters"],
        auth_token_id=request["auth_token_id"],
        principal=request["principal"],
        odoo_instance_id=request["odoo_instance_id"],
        database_name=request["database_name"],
        database_uuid=request["database_uuid"],
        company_id=request["company_id"],
        user_id=request["user_id"],
        registry_digest=request["registry_digest"],
        release_digest=request["release_digest"],
        environment=request["environment"],
        capability_channel=request["capability_channel"],
    )
    auth_witness = {
        "attempt_count": 1,
        "bound_parameters_sha256": request["parameters_sha256"],
        "expires_at": "2026-08-10T08:05:00Z",
        "not_before": "2026-08-10T07:55:00Z",
        "observed_at": NOW,
        "odoo_permission_granted": True,
    }
    if case_id == "acl_deny":
        auth_witness["odoo_permission_granted"] = False
    elif case_id == "expired":
        auth_witness["expires_at"] = NOW
    elif case_id == "replay":
        auth_witness["attempt_count"] = 2
    elif case_id == "tamper_parameters":
        auth_witness["bound_parameters_sha256"] = "0" * 64
    return request, auth_witness


def _security_case(
    capability_id: str, case_id: str, error_code: str
) -> dict[str, Any]:
    request, auth_witness = _security_request(capability_id, case_id)
    response = {
        "error_code": error_code,
        "error_message": f"rejected: {case_id}",
        "receipt": None,
        "request_id": request["request_id"],
        "result": None,
        "status": "error",
    }
    state = _digest({"security": capability_id, "state": "unchanged"})
    return {
        "auth_witness": auth_witness,
        "case_id": case_id,
        "exit_code": 6,
        "expected_error_code": error_code,
        "request": request,
        "request_sha256": _digest(request),
        "response": response,
        "response_sha256": _digest(response),
        "side_effect_witness": {
            "business_state_post_sha256": state,
            "business_state_pre_sha256": state,
            "cli_business_write_count": 0,
            "odoo_write_count": 0,
            "postgresql_write_count": 0,
            "receipt_count": 0,
            "result_count": 0,
        },
    }


def _release_case(capability_id: str) -> dict[str, Any]:
    return {
        "capability_contract_sha256": CONTRACTS[capability_id],
        "case_id": "release-identity",
        "observed_release_identity": deepcopy(IDENTITY),
        "release_identity_sha256": _digest(IDENTITY),
        "scope_sha256": SCOPE_SHA256,
    }


def _cases(kind: str, capability_id: str) -> list[dict[str, Any]]:
    if kind == "live_odoo":
        return [_live_case(capability_id)]
    if kind == "accounting_oracle":
        return [_oracle_case(capability_id)]
    if kind == "security_negative":
        return [
            _security_case(capability_id, case_id, error_code)
            for case_id, error_code in SECURITY_CASES
        ]
    if kind == "release_identity":
        return [_release_case(capability_id)]
    raise AssertionError(kind)


def _document(kind: str) -> dict[str, Any]:
    return {
        "capabilities": [
            {
                "capability_contract_sha256": CONTRACTS[capability_id],
                "capability_id": capability_id,
                "cases": _cases(kind, capability_id),
            }
            for capability_id in CAPABILITY_IDS
        ],
        "evidence_kind": kind,
        "release_identity": deepcopy(IDENTITY),
        "run_id": RUN_ID,
        "schema_version": raw_v3.FULL_RAW_EVIDENCE_SCHEMA,
        "scope_sha256": SCOPE_SHA256,
    }


def _validate(document: dict[str, Any]) -> dict[str, Any]:
    return raw_v3.validate_full_raw_evidence(
        document,
        expected_registry=REGISTRY,
        expected_scope=SCOPE,
        expected_scope_sha256=SCOPE_SHA256,
        expected_release_identity=IDENTITY,
        expected_run_id=RUN_ID,
    )


def _validate_with_scope(
    document: dict[str, Any], scope: dict[str, Any], scope_sha256: str
) -> dict[str, Any]:
    return raw_v3.validate_full_raw_evidence(
        document,
        expected_registry=REGISTRY,
        expected_scope=scope,
        expected_scope_sha256=scope_sha256,
        expected_release_identity=IDENTITY,
        expected_run_id=RUN_ID,
    )


@pytest.mark.parametrize(
    ("kind", "expected_case_count"),
    (
        ("accounting_oracle", 13),
        ("live_odoo", 13),
        ("release_identity", 13),
        ("security_negative", 65),
    ),
)
def test_full_raw_contracts_are_structurally_valid_but_not_trusted(
    kind: str, expected_case_count: int
) -> None:
    result = _validate(_document(kind))

    assert result["full_raw_contract_validated"] is True
    assert result["trusted_source_observed"] is False
    assert result["external_read_evidence_verified"] is False
    assert result["goal_evidence_admissible"] is False
    assert result["production_promotion_allowed"] is False
    assert result["receipt_signatures_verified"] is False
    assert result["oracle_execution_attested"] is False
    assert "goal_admissible" not in result
    assert result["evidence_kind"] == kind
    assert result["capability_count"] == 13
    assert result["case_count"] == expected_case_count
    assert result["raw_node_count"] > expected_case_count
    assert result["raw_size_bytes"] > 0
    expected_blockers = [raw_v3.TRUSTED_SOURCE_ADAPTER_BLOCKER]
    if kind == "accounting_oracle":
        expected_blockers.append(raw_v3.ORACLE_READ_ONLY_ATTESTATION_BLOCKER)
    assert result["blockers"] == expected_blockers
    assert [item["capability_id"] for item in result["capabilities"]] == list(
        CAPABILITY_IDS
    )


def test_public_api_exposes_no_source_trust_promotion_hook() -> None:
    assert raw_v3.__all__ == (
        "FULL_RAW_EVIDENCE_SCHEMA",
        "FULL_RAW_VALIDATION_REPORT_SCHEMA",
        "SCOPE_SCHEMA",
        "TRUSTED_SOURCE_ADAPTER_BLOCKER",
        "ORACLE_READ_ONLY_ATTESTATION_BLOCKER",
        "PI_TRUSTED_VERIFIER_BLOCKER",
        "FullRawEvidenceError",
        "validate_full_raw_evidence",
    )
    parameters = inspect.signature(raw_v3.validate_full_raw_evidence).parameters
    assert "expected_registry" in parameters
    assert "expected_capability_contracts" not in parameters


@pytest.mark.parametrize("capability_id", CAPABILITY_IDS)
def test_release_registry_fixtures_conform_to_real_contracts(
    capability_id: str,
) -> None:
    assert len(READ_CAPABILITIES) == 13
    capability = READ_CAPABILITIES[capability_id]
    execution = _execution(capability_id)
    validate_value(
        execution["request"]["parameters"], capability.data["input_schema"]
    )
    validate_value(
        {
            **execution["response"]["result_body"],
            "receipt": execution["receipt"],
        },
        capability.data["output_schema"],
    )


def test_normalized_only_document_is_rejected() -> None:
    normalized = {
        "capabilities": [
            {
                "capability_contract_sha256": CONTRACTS[capability_id],
                "capability_id": capability_id,
                "case": {"request_sha256": "a" * 64},
            }
            for capability_id in CAPABILITY_IDS
        ],
        "evidence_kind": "live_odoo",
        "release_identity": deepcopy(IDENTITY),
        "run_id": RUN_ID,
        "schema_version": "odoo-accounting-cli-v3.read-evidence-raw.v3",
        "scope_sha256": SCOPE_SHA256,
    }

    with pytest.raises(raw_v3.FullRawEvidenceError, match="full-raw schema"):
        _validate(normalized)


@pytest.mark.parametrize("mutation", ["missing", "extra"])
def test_root_requires_exact_fields(mutation: str) -> None:
    document = _document("live_odoo")
    if mutation == "missing":
        del document["run_id"]
    else:
        document["trusted"] = True

    with pytest.raises(raw_v3.FullRawEvidenceError, match="fields"):
        _validate(document)


@pytest.mark.parametrize("mutation", ["missing", "extra"])
def test_nested_request_requires_exact_fields(mutation: str) -> None:
    document = _document("live_odoo")
    request = document["capabilities"][0]["cases"][0]["execution"]["request"]
    if mutation == "missing":
        del request["principal"]
    else:
        request["caller_claimed_trusted"] = True

    with pytest.raises(raw_v3.FullRawEvidenceError, match="request fields"):
        _validate(document)


def test_capability_coverage_and_order_are_exact() -> None:
    missing = _document("live_odoo")
    missing["capabilities"].pop()
    with pytest.raises(raw_v3.FullRawEvidenceError, match="coverage"):
        _validate(missing)

    reordered = _document("live_odoo")
    reordered["capabilities"][0], reordered["capabilities"][1] = (
        reordered["capabilities"][1],
        reordered["capabilities"][0],
    )
    with pytest.raises(raw_v3.FullRawEvidenceError, match="sorted"):
        _validate(reordered)


def test_contract_scope_release_run_and_capability_bindings_are_exact() -> None:
    mutations = []

    contract = _document("live_odoo")
    contract["capabilities"][0]["capability_contract_sha256"] = "f" * 64
    mutations.append(contract)

    scope = _document("live_odoo")
    scope["scope_sha256"] = "e" * 64
    mutations.append(scope)

    release = _document("live_odoo")
    release["release_identity"]["package_sha256"] = "d" * 64
    mutations.append(release)

    run = _document("live_odoo")
    run["run_id"] = "run-incorrect"
    mutations.append(run)

    capability = _document("live_odoo")
    capability["capabilities"][0]["cases"][0]["execution"]["request"][
        "capability_id"
    ] = CAPABILITY_IDS[1]
    mutations.append(capability)

    for document in mutations:
        with pytest.raises(raw_v3.FullRawEvidenceError, match="mismatch"):
            _validate(document)


@pytest.mark.parametrize("mutation", ["schema", "extra", "digest"])
def test_expected_scope_is_exact_and_canonically_digest_bound(
    mutation: str,
) -> None:
    scope = deepcopy(SCOPE)
    scope_sha256 = SCOPE_SHA256
    if mutation == "schema":
        scope["schema_version"] = "attacker.scope.v999"
    elif mutation == "extra":
        scope["principal"] = "caller-injected"
    else:
        scope_sha256 = "f" * 64

    with pytest.raises(raw_v3.FullRawEvidenceError, match="expected scope"):
        _validate_with_scope(_document("live_odoo"), scope, scope_sha256)


def test_release_registry_digest_is_bound_to_release_identity() -> None:
    identity = {**IDENTITY, "registry_digest": "f" * 64}
    with pytest.raises(raw_v3.FullRawEvidenceError, match="registry digest"):
        raw_v3.validate_full_raw_evidence(
            _document("live_odoo"),
            expected_registry=REGISTRY,
            expected_scope=SCOPE,
            expected_scope_sha256=SCOPE_SHA256,
            expected_release_identity=identity,
            expected_run_id=RUN_ID,
        )


@pytest.mark.parametrize("expected_registry", [list(REGISTRY), REGISTRY[:-1]])
def test_expected_registry_must_be_the_complete_validated_tuple(
    expected_registry: object,
) -> None:
    with pytest.raises(raw_v3.FullRawEvidenceError, match="expected registry"):
        raw_v3.validate_full_raw_evidence(
            _document("live_odoo"),
            expected_registry=expected_registry,  # type: ignore[arg-type]
            expected_scope=SCOPE,
            expected_scope_sha256=SCOPE_SHA256,
            expected_release_identity=IDENTITY,
            expected_run_id=RUN_ID,
        )


def test_parameter_tamper_rehashed_locally_still_breaks_receipt_binding() -> None:
    document = _document("live_odoo")
    execution = document["capabilities"][0]["cases"][0]["execution"]
    request = execution["request"]
    request["parameters"]["as_of_date"] = "2026-08-31"
    request["parameters_sha256"] = _digest(request["parameters"])
    request["request_digest"] = read_request_digest(
        capability_id=request["capability_id"],
        parameters=request["parameters"],
        auth_token_id=request["auth_token_id"],
        principal=request["principal"],
        odoo_instance_id=request["odoo_instance_id"],
        database_name=request["database_name"],
        database_uuid=request["database_uuid"],
        company_id=request["company_id"],
        user_id=request["user_id"],
        registry_digest=request["registry_digest"],
        release_digest=request["release_digest"],
        environment=request["environment"],
        capability_channel=request["capability_channel"],
    )
    execution["source_witness"]["request_sha256"] = _digest(request)

    with pytest.raises(raw_v3.FullRawEvidenceError, match="receipt request"):
        _validate(document)


def test_multicompany_parameters_cannot_escape_authenticated_scope() -> None:
    document = _document("live_odoo")
    capability = next(
        item
        for item in document["capabilities"]
        if item["capability_id"]
        == "acct.multicompany.consolidated_read.v1"
    )
    execution = capability["cases"][0]["execution"]
    execution["request"]["parameters"]["company_ids"] = [999]
    _rebind_request(execution)

    with pytest.raises(raw_v3.FullRawEvidenceError, match="company binding"):
        _validate(document)


def test_single_company_output_cannot_rehash_a_cross_company_filter() -> None:
    document = _document("live_odoo")
    capability = next(
        item
        for item in document["capabilities"]
        if item["capability_id"] == "acct.ar.open_items.v1"
    )
    execution = capability["cases"][0]["execution"]
    execution["response"]["result_body"]["filters"]["company_id"] = 999
    _rebind_response(execution)

    with pytest.raises(raw_v3.FullRawEvidenceError, match="company"):
        _validate(document)


def test_multicompany_output_filter_must_echo_requested_companies() -> None:
    document = _document("live_odoo")
    capability = next(
        item
        for item in document["capabilities"]
        if item["capability_id"]
        == "acct.multicompany.consolidated_read.v1"
    )
    execution = capability["cases"][0]["execution"]
    assert execution["request"]["parameters"]["company_ids"] == [1]
    execution["response"]["result_body"]["filters"]["company_ids"] = [2]
    _rebind_response(execution)

    with pytest.raises(raw_v3.FullRawEvidenceError, match="company"):
        _validate(document)


def test_rate_root_company_is_not_misclassified_as_business_scope() -> None:
    document = _document("live_odoo")
    capability = next(
        item
        for item in document["capabilities"]
        if item["capability_id"]
        == "acct.multicompany.consolidated_read.v1"
    )
    execution = capability["cases"][0]["execution"]
    translation_rate = execution["response"]["result_body"]["companies"][0][
        "translation_rate"
    ]
    translation_rate["rate_company_id"] = 2
    translation_rate["source_technical_source"]["source_company_id"] = 2
    translation_rate["presentation_technical_source"]["source_company_id"] = 2
    _rebind_response(execution)

    result = _validate(document)
    assert result["full_raw_contract_validated"] is True
    assert result["trusted_source_observed"] is False
    assert result["goal_evidence_admissible"] is False


def test_multicompany_company_payload_must_exactly_cover_request() -> None:
    document = _document("live_odoo")
    capability = next(
        item
        for item in document["capabilities"]
        if item["capability_id"]
        == "acct.multicompany.consolidated_read.v1"
    )
    execution = capability["cases"][0]["execution"]
    company = execution["response"]["result_body"]["companies"][0]
    company["company_id"] = 2
    company["translation_rate"]["company_id"] = 2
    _rebind_response(execution)

    with pytest.raises(raw_v3.FullRawEvidenceError, match="company"):
        _validate(document)


@pytest.mark.parametrize(
    ("capability_id", "path"),
    (
        (
            "acct.move.document_post_eligibility.v1",
            ("target", "company_id"),
        ),
        (
            "acct.diagnostics.operation_read.v1",
            ("operation", "company_id"),
        ),
        (
            "acct.refund.draft_cancel_eligibility.v1",
            ("target", "origin", "company_id"),
        ),
        (
            "acct.refund.post_reconcile_eligibility.v1",
            ("target", "origin", "company_id"),
        ),
    ),
)
def test_explicit_output_company_paths_are_request_bound(
    capability_id: str, path: tuple[str, ...]
) -> None:
    document = _document("live_odoo")
    capability = next(
        item
        for item in document["capabilities"]
        if item["capability_id"] == capability_id
    )
    execution = capability["cases"][0]["execution"]
    target = execution["response"]["result_body"]
    for field in path[:-1]:
        target = target[field]
    target[path[-1]] = 999
    _rebind_response(execution)

    with pytest.raises(raw_v3.FullRawEvidenceError, match="company"):
        _validate(document)


def test_multicurrency_global_rate_cannot_claim_a_company_source() -> None:
    document = _document("live_odoo")
    capability = next(
        item
        for item in document["capabilities"]
        if item["capability_id"] == "acct.multicurrency.balance_read.v1"
    )
    execution = capability["cases"][0]["execution"]
    source = execution["response"]["result_body"]["rates"][0][
        "transaction_technical_source"
    ]
    source["effective_date"] = "2026-07-31"
    source["source_company_id"] = 1
    source["source_model"] = "res.currency.rate"
    source["source_record_id"] = 1
    source["source_scope"] = "global"
    _rebind_response(execution)

    with pytest.raises(raw_v3.FullRawEvidenceError, match="company"):
        _validate(document)


@pytest.mark.parametrize("location", ("query_parameters", "source_records"))
def test_oracle_company_references_cannot_escape_requested_scope(
    location: str,
) -> None:
    document = _document("accounting_oracle")
    capability = next(
        item
        for item in document["capabilities"]
        if item["capability_id"] == "acct.gl.trial_balance.v1"
    )
    case = capability["cases"][0]
    if location == "query_parameters":
        case["oracle_definition"]["query_parameters"]["company_id"] = 999
    else:
        case["source_records"][0]["company_id"] = 999
    case["source_records_sha256"] = _digest(case["source_records"])
    witness = case["oracle_witness"]
    witness["source_records_sha256"] = case["source_records_sha256"]
    witness["oracle_definition_sha256"] = _digest(case["oracle_definition"])
    witness["oracle_input_sha256"] = _digest(
        {
            "oracle_definition": case["oracle_definition"],
            "parameters": case["execution"]["request"]["parameters"],
            "source_records": case["source_records"],
        }
    )

    with pytest.raises(raw_v3.FullRawEvidenceError, match="oracle"):
        _validate(document)


@pytest.mark.parametrize("location", ("query_parameters", "source_records"))
def test_oracle_cannot_hide_an_additional_company_parameter(
    location: str,
) -> None:
    document = _document("accounting_oracle")
    capability = next(
        item
        for item in document["capabilities"]
        if item["capability_id"] == "acct.gl.trial_balance.v1"
    )
    case = capability["cases"][0]
    if location == "query_parameters":
        case["oracle_definition"]["query_parameters"][
            "attacker_company_id"
        ] = 999
    else:
        case["source_records"][0]["actual_company_id"] = 999
    case["source_records_sha256"] = _digest(case["source_records"])
    witness = case["oracle_witness"]
    witness["source_records_sha256"] = case["source_records_sha256"]
    witness["oracle_definition_sha256"] = _digest(case["oracle_definition"])
    witness["oracle_input_sha256"] = _digest(
        {
            "oracle_definition": case["oracle_definition"],
            "parameters": case["execution"]["request"]["parameters"],
            "source_records": case["source_records"],
        }
    )

    with pytest.raises(raw_v3.FullRawEvidenceError, match="oracle"):
        _validate(document)


def test_multicompany_business_rule_oracle_uses_company_ids() -> None:
    document = _document("accounting_oracle")
    capability = next(
        item
        for item in document["capabilities"]
        if item["capability_id"]
        == "acct.multicompany.consolidated_read.v1"
    )
    case = capability["cases"][0]
    parameters = case["execution"]["request"]["parameters"]
    definition = {
        "oracle_code_sha256": _digest({"oracle": "multicompany-rule"}),
        "oracle_id": "oracle-multicompany-rule",
        "oracle_type": "business_rule",
        "rule_inputs": deepcopy(parameters),
        "rule_inputs_sha256": _digest(parameters),
        "ruleset_sha256": _digest({"ruleset": "multicompany-rule"}),
    }
    case["oracle_definition"] = definition
    witness = case["oracle_witness"]
    witness["boundary_mode"] = "snapshot_comparison"
    witness["oracle_definition_sha256"] = _digest(definition)
    witness["oracle_input_sha256"] = _digest(
        {
            "oracle_definition": definition,
            "parameters": parameters,
            "source_records": case["source_records"],
        }
    )
    witness["oracle_type"] = "business_rule"
    witness["rolled_back"] = False

    result = _validate(document)
    assert result["full_raw_contract_validated"] is True
    assert result["oracle_execution_attested"] is False
    assert result["goal_evidence_admissible"] is False


@pytest.mark.parametrize(
    ("source_scope", "source_company_id"),
    (
        ("company_specific", 999),
        ("global", None),
        ("no_rate_identity", None),
    ),
)
def test_oracle_rate_source_company_is_not_a_business_company(
    source_scope: str,
    source_company_id: int | None,
) -> None:
    document = _document("accounting_oracle")
    capability = next(
        item
        for item in document["capabilities"]
        if item["capability_id"] == "acct.multicurrency.balance_read.v1"
    )
    case = capability["cases"][0]
    source_record = case["source_records"][0]
    source_record["rate_company_id"] = 999
    source_record["source_company_id"] = source_company_id
    source_record["source_scope"] = source_scope
    case["source_records_sha256"] = _digest(case["source_records"])
    witness = case["oracle_witness"]
    witness["source_records_sha256"] = case["source_records_sha256"]
    witness["oracle_input_sha256"] = _digest(
        {
            "oracle_definition": case["oracle_definition"],
            "parameters": case["execution"]["request"]["parameters"],
            "source_records": case["source_records"],
        }
    )

    result = _validate(document)
    assert result["full_raw_contract_validated"] is True
    assert result["oracle_execution_attested"] is False
    assert result["goal_evidence_admissible"] is False


@pytest.mark.parametrize(
    ("source_scope", "rate_company_id", "source_company_id"),
    (
        ("company_specific", 999, 888),
        ("company_specific", 999, None),
        ("global", 999, 999),
        ("no_rate_identity", 999, 999),
    ),
)
def test_oracle_rate_source_company_relationship_is_strict(
    source_scope: str,
    rate_company_id: int,
    source_company_id: int | None,
) -> None:
    document = _document("accounting_oracle")
    capability = next(
        item
        for item in document["capabilities"]
        if item["capability_id"] == "acct.multicurrency.balance_read.v1"
    )
    case = capability["cases"][0]
    source_record = case["source_records"][0]
    source_record["rate_company_id"] = rate_company_id
    source_record["source_company_id"] = source_company_id
    source_record["source_scope"] = source_scope
    case["source_records_sha256"] = _digest(case["source_records"])
    witness = case["oracle_witness"]
    witness["source_records_sha256"] = case["source_records_sha256"]
    witness["oracle_input_sha256"] = _digest(
        {
            "oracle_definition": case["oracle_definition"],
            "parameters": case["execution"]["request"]["parameters"],
            "source_records": case["source_records"],
        }
    )

    with pytest.raises(raw_v3.FullRawEvidenceError, match="oracle"):
        _validate(document)


def test_request_parameters_must_match_real_input_schema() -> None:
    document = _document("live_odoo")
    execution = document["capabilities"][0]["cases"][0]["execution"]
    execution["request"]["parameters"].pop("as_of_date")
    _rebind_request(execution)

    with pytest.raises(raw_v3.FullRawEvidenceError, match="input schema"):
        _validate(document)


def test_response_body_and_receipt_must_match_real_output_schema() -> None:
    document = _document("live_odoo")
    execution = document["capabilities"][0]["cases"][0]["execution"]
    execution["response"]["result_body"].pop("basis")
    _rebind_response(execution)

    with pytest.raises(raw_v3.FullRawEvidenceError, match="output schema"):
        _validate(document)


def test_response_tamper_rehashed_locally_still_breaks_receipt_binding() -> None:
    document = _document("live_odoo")
    execution = document["capabilities"][0]["cases"][0]["execution"]
    response = execution["response"]
    response["result_body"]["basis"] = "tampered"
    response["result_sha256"] = _digest(response["result_body"])
    execution["source_witness"]["response_sha256"] = _digest(response)

    with pytest.raises(raw_v3.FullRawEvidenceError, match="receipt result"):
        _validate(document)


def test_oracle_source_rehash_does_not_rebind_witness() -> None:
    document = _document("accounting_oracle")
    case = document["capabilities"][0]["cases"][0]
    case["source_records"][0]["value"] = "999.00"
    case["source_records_sha256"] = _digest(case["source_records"])

    with pytest.raises(raw_v3.FullRawEvidenceError, match="source records"):
        _validate(document)


def test_typed_oracle_rejects_sql_for_durable_store_capability() -> None:
    document = _document("accounting_oracle")
    diagnostics = next(
        item
        for item in document["capabilities"]
        if item["capability_id"] == "acct.diagnostics.operation_read.v1"
    )
    diagnostics_case = diagnostics["cases"][0]
    diagnostics_case["oracle_definition"] = _oracle_definition(
        "acct.gl.trial_balance.v1",
        diagnostics_case["execution"]["request"]["parameters"],
    )

    with pytest.raises(raw_v3.FullRawEvidenceError, match="oracle type"):
        _validate(document)


def test_sql_oracle_text_cannot_claim_verified_read_only_attestation() -> None:
    document = _document("accounting_oracle")
    capability = next(
        item
        for item in document["capabilities"]
        if _oracle_type(item["capability_id"]) == "postgresql_sql"
    )
    case = capability["cases"][0]
    definition = case["oracle_definition"]
    query_text = "DELETE FROM account_move_line WHERE company_id = %(company_id)s"
    definition["query_text"] = query_text
    definition["query_sha256"] = _digest(query_text)
    witness = case["oracle_witness"]
    witness["oracle_definition_sha256"] = _digest(definition)
    witness["oracle_input_sha256"] = _digest(
        {
            "oracle_definition": definition,
            "parameters": case["execution"]["request"]["parameters"],
            "source_records": case["source_records"],
        }
    )

    result = _validate(document)

    assert raw_v3.ORACLE_READ_ONLY_ATTESTATION_BLOCKER in result["blockers"]
    assert result["external_read_evidence_verified"] is False
    assert result["goal_evidence_admissible"] is False
    assert result["production_promotion_allowed"] is False
    assert result["receipt_signatures_verified"] is False


def test_pi_full_raw_is_delegated_to_existing_trusted_verifier() -> None:
    document = _document("live_odoo")
    document["evidence_kind"] = "pi_e2e"

    with pytest.raises(
        raw_v3.FullRawEvidenceError,
        match="PiEvidenceVerifier",
    ):
        _validate(document)


def test_security_raw_response_rehash_does_not_change_required_error() -> None:
    document = _document("security_negative")
    case = document["capabilities"][0]["cases"][0]
    case["response"]["error_code"] = "unexpected_error"
    case["response_sha256"] = _digest(case["response"])

    with pytest.raises(raw_v3.FullRawEvidenceError, match="error code"):
        _validate(document)


def test_security_case_specific_attack_witness_is_required() -> None:
    document = _document("security_negative")
    cases = document["capabilities"][0]["cases"]
    acl_case = cases[0]
    acl_case["auth_witness"]["odoo_permission_granted"] = True
    with pytest.raises(raw_v3.FullRawEvidenceError, match="ACL denial"):
        _validate(document)


def test_security_zero_side_effect_witness_is_strict() -> None:
    document = _document("security_negative")
    case = document["capabilities"][0]["cases"][0]
    case["side_effect_witness"]["odoo_write_count"] = 1

    with pytest.raises(raw_v3.FullRawEvidenceError, match="side effects"):
        _validate(document)


def test_registry_allowed_total_count_is_not_a_source_record_expansion() -> None:
    document = _document("live_odoo")
    capability = next(
        item
        for item in document["capabilities"]
        if item["capability_id"] == "acct.report.financial_read.v1"
    )
    execution = capability["cases"][0]["execution"]
    execution["response"]["record_count"] = 10_001
    execution["response"]["result_body"]["page"]["total_count"] = 10_001
    _rebind_response(execution)
    validate_value(
        {
            **execution["response"]["result_body"],
            "receipt": execution["receipt"],
        },
        READ_CAPABILITIES["acct.report.financial_read.v1"].data[
            "output_schema"
        ],
    )

    result = _validate(document)
    assert result["full_raw_contract_validated"] is True


@pytest.mark.parametrize("location", ("key", "value"))
def test_unpaired_unicode_surrogate_is_structurally_rejected(location: str) -> None:
    document = _document("live_odoo")
    if location == "key":
        document["\ud800"] = "invalid"
    else:
        document["run_id"] = "\ud800"

    with pytest.raises(raw_v3.FullRawEvidenceError, match="UTF-8"):
        _validate(document)


def test_boolean_is_not_accepted_as_an_integer() -> None:
    document = _document("security_negative")
    document["capabilities"][0]["cases"][0]["exit_code"] = True

    with pytest.raises(raw_v3.FullRawEvidenceError, match="exit_code"):
        _validate(document)
