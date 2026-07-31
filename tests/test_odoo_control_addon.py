from __future__ import annotations

import ast
import csv
import xml.etree.ElementTree as ET
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ADDON = ROOT / "odoo_addons" / "odoo_accounting_cli_v3_control"
MODEL = ADDON / "models" / "operation.py"
SECURITY = ADDON / "security" / "odoo_accounting_cli_v3_security.xml"
ACL = ADDON / "security" / "ir.model.access.csv"


def _manifest() -> dict:
    return ast.literal_eval((ADDON / "__manifest__.py").read_text(encoding="utf-8"))


def _source() -> str:
    return MODEL.read_text(encoding="utf-8")


def _model_class() -> ast.ClassDef:
    tree = ast.parse(_source())
    return next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef)
        and node.name == "OdooAccountingCliOperation"
    )


def _method(name: str) -> ast.FunctionDef:
    return next(
        node
        for node in _model_class().body
        if isinstance(node, ast.FunctionDef) and node.name == name
    )


def _frozenset_assignment(name: str) -> set[str]:
    assignment = next(
        node
        for node in _model_class().body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == name for target in node.targets)
    )
    assert isinstance(assignment.value, ast.Call)
    values = assignment.value.args[0]
    assert isinstance(values, ast.Set)
    return {ast.literal_eval(element) for element in values.elts}


def _record_fields(record: ET.Element) -> dict[str, ET.Element]:
    return {field.attrib["name"]: field for field in record.findall("field")}


def test_control_addon_is_odoo_19_scoped_and_loadable_as_a_static_package():
    manifest = _manifest()

    assert manifest["version"].startswith("19.0.")
    assert manifest["depends"] == ["base", "account"]
    assert manifest["data"] == [
        "security/odoo_accounting_cli_v3_security.xml",
        "security/ir.model.access.csv",
        "views/approval_wizard_views.xml",
    ]
    assert manifest["installable"] is True
    assert manifest["application"] is False
    for relative_path in manifest["data"]:
        assert (ADDON / relative_path).is_file()

    assert (ADDON / "__init__.py").read_text(encoding="utf-8").strip() == (
        "from . import models"
    )
    assert (ADDON / "models" / "__init__.py").read_text(
        encoding="utf-8"
    ).splitlines() == [
        "from . import execution_scope",
        "from . import accounting_metadata",
        "from . import bank_statement_sequence_guard",
        "from . import approval_client",
        "from . import approval_wizard",
        "from . import module_guard",
        "from . import operation",
        "from . import mail_thread_projection",
        "from . import session_client",
    ]
    for python_file in ADDON.rglob("*.py"):
        ast.parse(python_file.read_text(encoding="utf-8"), filename=str(python_file))


def test_control_addon_persists_approved_accounting_and_bank_source_metadata():
    source = (ADDON / "models" / "accounting_metadata.py").read_text(
        encoding="utf-8"
    )

    assert '_inherit = "account.move"' in source
    assert '_inherit = "account.move.line"' in source
    assert '_inherit = "account.payment"' in source
    assert '_inherit = "account.bank.statement"' in source
    assert '_inherit = "account.bank.statement.line"' in source
    assert "odoo_cli_v3_reason = fields.Char(copy=False, index=True)" in source
    assert "odoo_cli_v3_period_end_date = fields.Date(copy=False, index=True)" in source
    assert "odoo_cli_v3_document_binding = fields.Char(" in source
    assert "UNIQUE(company_id, move_type, odoo_cli_v3_document_binding)" in source
    assert "odoo_cli_v3_business_binding = fields.Char(" in source
    assert "UNIQUE(company_id, move_type, odoo_cli_v3_business_binding)" in source
    assert "odoo_cli_v3_line_reference = fields.Char(copy=False, index=True)" in source
    assert "odoo_cli_v3_payment_binding = fields.Json(copy=False)" in source
    for field in (
        "odoo_cli_v3_external_reference",
        "odoo_cli_v3_source_digest",
        "odoo_cli_v3_source_filename",
        "odoo_cli_v3_external_transaction_id",
        "odoo_cli_v3_source_line_digest",
        "odoo_cli_v3_value_date",
    ):
        assert field in source
    assert "UNIQUE(journal_id, odoo_cli_v3_external_reference)" in source
    assert "UNIQUE(journal_id, odoo_cli_v3_source_digest)" in source
    assert "UNIQUE(journal_id, odoo_cli_v3_external_transaction_id)" in source
    assert "UNIQUE(journal_id, odoo_cli_v3_source_line_digest)" in source
    assert "bank source identity fields are immutable" in source
    assert "accounting move metadata fields are immutable" in source
    assert "document binding must be lowercase SHA-256" in source
    assert "business binding must be lowercase SHA-256" in source
    assert "accounting line metadata fields are immutable" in source
    assert "payment binding is immutable" in source
    assert "bank source digest must be lowercase SHA-256" in source


def test_control_model_uses_odoo_19_constraints_and_exact_anchor_fields():
    source = _source()
    immutable = _frozenset_assignment("_IMMUTABLE_FIELDS")
    mutable = _frozenset_assignment("_MUTABLE_FIELDS")

    assert '_name = "odoo.accounting.cli.operation"' in source
    assert "_check_company_auto = True" in source
    assert "_operation_id_unique = models.Constraint(" in source
    assert '"UNIQUE(operation_id)"' in source
    assert "_company_capability_scope_unique = models.Constraint(" in source
    assert '"UNIQUE(company_id, capability_id, idempotency_scope)"' in source
    assert "_sql_constraints" not in source
    assert immutable == {
        "operation_id",
        "request_id",
        "capability_id",
        "idempotency_scope",
        "operation_digest",
        "protocol_version",
        "precheck_digest",
        "principal",
        "requester_id",
        "approver_id",
        "company_id",
        "environment",
        "capability_channel",
        "registry_digest",
        "release_digest",
    }
    assert mutable == {
        "state",
        "execution_evidence_json",
        "execution_evidence_digest",
        "verification_evidence_json",
        "verification_evidence_digest",
        "failure_evidence_json",
        "failure_evidence_digest",
        "recovery_plan_json",
        "recovery_plan_digest",
        "recovery_evidence_json",
        "recovery_evidence_digest",
        "execution_result_json",
        "execution_result_digest",
        "verification_result_json",
        "verification_result_digest",
        "recovery_result_json",
        "recovery_result_digest",
    }
    assert immutable.isdisjoint(mutable)
    assert '_CREATE_FIELDS = _IMMUTABLE_FIELDS | {"state"}' in source
    assert "if set(values) != self._CREATE_FIELDS:" in source
    assert 'if values.get("protocol_version") != 4:' in source
    assert 'self._required_digest(values.get(field_name), field_name)' in source


def test_control_model_rejects_unsafe_orm_escape_hatches():
    source = _source()
    tree = ast.parse(source)
    forbidden_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in {"sudo", "commit", "unlink"}
    ]
    assert forbidden_calls == []
    assert ".sudo(" not in source
    assert ".commit(" not in source
    assert "env.cr.commit" not in source

    for method_name, message in (
        ("write", "direct control operation writes are forbidden"),
        ("unlink", "control operations cannot be deleted"),
    ):
        method = _method(method_name)
        assert len(method.body) == 1
        assert isinstance(method.body[0], ast.Raise)
        assert message in ast.get_source_segment(source, method.body[0])

    sql_literals = {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and node.value.lstrip().upper().startswith(("SELECT ", "INSERT ", "UPDATE ", "DELETE "))
    }
    assert sql_literals == {"SELECT pg_advisory_xact_lock(%s)"}


def test_control_model_exposes_no_bootstrap_mutation_method_to_rpc():
    source = _source()
    methods = {
        node.name: node
        for node in _model_class().body
        if isinstance(node, ast.FunctionDef)
    }
    bootstrap_methods = {
        "lookup_exact",
        "claim",
        "acquire_resource_locks",
        "record_execution",
        "record_verification",
        "record_committed_verification_from_root",
        "record_failure",
        "begin_recovery",
        "record_recovery",
    }

    assert {name for name in methods if not name.startswith("_")} == {
        "create",
        "write",
        "unlink",
    }
    assert {f"_{name}" for name in bootstrap_methods} <= set(methods)
    for method_name in ("create", "write", "unlink"):
        method = methods[method_name]
        assert len(method.body) == 1
        assert isinstance(method.body[0], ast.Raise)
        assert ast.get_source_segment(source, method.body[0]).startswith(
            "raise AccessError("
        )

    controlled_create = ast.get_source_segment(
        source, methods["_create_controlled"]
    )
    claim = ast.get_source_segment(source, methods["_claim"])
    assert "return super().create(vals_list)" in controlled_create
    assert "return self._create_controlled(" in claim
    assert "self.create(" not in claim
    assert ".with_context(" not in source
    assert "env.context" not in source


def test_claim_and_every_transition_require_the_bound_executor_and_company():
    source = _source()
    executor_guard = ast.get_source_segment(source, _method("_assert_executor"))
    bound_guard = ast.get_source_segment(source, _method("_assert_bound_executor"))
    claim_guard = ast.get_source_segment(source, _method("_assert_claim_binding"))

    assert "self.env.su" in executor_guard
    assert "self.env.user.has_group" in executor_guard
    assert "odoo_accounting_cli_v3_control.group_executor" in executor_guard
    assert "self.requester_id.id != self.env.uid" in bound_guard
    assert "self.company_id.id not in self.env.companies.ids" in bound_guard
    assert "requester_id != self.env.uid" in claim_guard
    assert "company_id not in self.env.user.company_ids.ids" in claim_guard
    assert "company_id not in self.env.companies.ids" in claim_guard

    for method_name in (
        "_record_execution",
        "_record_verification",
        "_record_failure",
        "_begin_recovery",
        "_record_recovery",
    ):
        method = _method(method_name)
        first_calls = [
            statement.value.func.attr
            for statement in method.body[:2]
            if isinstance(statement, ast.Expr)
            and isinstance(statement.value, ast.Call)
            and isinstance(statement.value.func, ast.Attribute)
        ]
        assert first_calls == ["ensure_one", "_assert_bound_executor"]

    claim_source = ast.get_source_segment(source, _method("_claim"))
    create_source = ast.get_source_segment(source, _method("_create_controlled"))
    assert "self._assert_claim_binding(requester_id, company_id)" in claim_source
    assert "self._assert_claim_binding(requester_id, company_id)" in create_source
    assert "approver_id == requester_id" in create_source
    assert "not approver.active" in create_source
    assert "company_id not in approver.company_ids.ids" in create_source
    assert "odoo_accounting_cli_v3_control.group_approver" in create_source
    assert 'environment == "production" and capability_channel == "staged"' in create_source


def test_resource_locks_are_bound_ordered_and_digest_only():
    source = _source()
    method = _method("_acquire_resource_locks")
    method_source = ast.get_source_segment(source, method)

    assert "self.ensure_one()" in method_source
    assert "self._assert_bound_executor()" in method_source
    assert "self.state != \"claimed\"" in method_source
    assert "len(resource_digests) > 2000" in method_source
    assert "resource_digests != sorted(set(resource_digests))" in method_source
    assert "self._required_digest(resource_digest" in method_source
    assert "self._acquire_scope_lock(resource_digest)" in method_source


def test_idempotent_replay_compares_every_immutable_identity_field():
    source = _source()
    claim = _method("_claim")
    compared_existing_fields = {
        node.attr
        for node in ast.walk(claim)
        if isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "existing"
    }

    assert _frozenset_assignment("_IMMUTABLE_FIELDS") <= compared_existing_fields
    assert "pg_advisory_xact_lock" in source
    assert "idempotency scope has different immutable content" in source
    assert "self._acquire_scope_lock(idempotency_scope)" in ast.get_source_segment(
        source, claim
    )


def test_exact_lookup_is_root_only_and_compares_the_complete_immutable_binding():
    source = _source()
    lookup = _method("_lookup_exact")
    lookup_source = ast.get_source_segment(source, lookup)
    immutable = _frozenset_assignment("_IMMUTABLE_FIELDS")

    assert {argument.arg for argument in lookup.args.kwonlyargs} == immutable
    assert "if not self.env.su:" in lookup_source
    assert "exact operation lookup is restricted to the root control plane" in lookup_source
    assert 'self.search([("operation_id", "=", operation_id)], limit=2)' in lookup_source
    assert "if len(anchor) != 1:" in lookup_source
    assert "operation lookup immutable binding mismatch" in lookup_source
    assert "_assert_executor" not in lookup_source
    assert "_write_controlled" not in lookup_source


def test_state_transitions_and_canonical_evidence_are_fail_closed():
    source = _source()

    for marker in (
        'self.state != "claimed"',
        '"state": "committed" if succeeded else "failed"',
        'self.state != "committed"',
        '"state": "verified" if passed else "failed"',
        'self.state not in {"verified", "failed"}',
        '"state": "recovering"',
        'self.state != "recovering"',
        '"state": "recovered" if succeeded else "failed"',
        "type(succeeded) is not bool",
        "type(passed) is not bool",
    ):
        assert marker in source

    for method_name in (
        "_record_execution",
        "_record_verification_controlled",
        "_begin_recovery",
        "_record_recovery",
    ):
        method_source = ast.get_source_segment(source, _method(method_name))
        assert "self._canonical_evidence(" in method_source
        assert "self._write_controlled(" in method_source

    for marker in (
        "isinstance(evidence, dict)",
        "ensure_ascii=False",
        "allow_nan=False",
        "sort_keys=True",
        'separators=(",", ":")',
        "hashlib.sha256(encoded.encode(\"utf-8\")).hexdigest()",
        "canonical evidence digest mismatch",
        '_SHA256 = re.compile(r"[0-9a-f]{64}")',
    ):
        assert marker in source


def test_signed_result_envelopes_are_canonical_bound_and_replayable():
    source = _source()

    assert _frozenset_assignment("_RESULT_ENVELOPE_FIELDS") == {
        "capability_id",
        "company_id",
        "evidence_digest",
        "issued_at",
        "issuer",
        "key_id",
        "kind",
        "operation_digest",
        "operation_id",
        "operation_revision",
        "operation_state_digest",
        "prior_evidence_digest",
        "purpose",
        "registry_digest",
        "release_digest",
        "request_id",
        "signature",
        "succeeded",
        "version",
    }
    assert _frozenset_assignment("_RESULT_STORAGE_FIELDS") == {
        "execution_evidence_json",
        "execution_evidence_digest",
        "execution_result_json",
        "execution_result_digest",
        "verification_evidence_json",
        "verification_evidence_digest",
        "verification_result_json",
        "verification_result_digest",
        "recovery_evidence_json",
        "recovery_evidence_digest",
        "recovery_result_json",
        "recovery_result_digest",
    }

    for field_name in (
        "execution_result_json",
        "execution_result_digest",
        "verification_result_json",
        "verification_result_digest",
        "recovery_result_json",
        "recovery_result_digest",
    ):
        assert f"{field_name} = fields." in source
        field_line = next(
            line for line in source.splitlines() if line.strip().startswith(f"{field_name} =")
        )
        assert "readonly=True" in field_line
        assert "copy=False" in field_line
    for marker in (
        "_RESULT_ENVELOPE_FIELDS",
        "_RESULT_PURPOSES",
        "def _canonical_result_envelope(",
        "def _is_same_result_replay(",
        "set(result) != self._RESULT_ENVELOPE_FIELDS",
        'result["evidence_digest"] != evidence_digest',
        'result["operation_id"] != self.operation_id',
        'result["request_id"] != self.request_id',
        'result["operation_digest"] != self.operation_digest',
        'result["company_id"] != self.company_id.id',
        'result["capability_id"] != self.capability_id',
        'result["registry_digest"] != self.registry_digest',
        'result["release_digest"] != self.release_digest',
        'result["succeeded"] is not succeeded',
        "result envelope digest mismatch",
        "result envelope is immutable",
        "return existing",
        '"execution": "execution_result_v2"',
        '"verification": "verification_result_v2"',
        '"recovery": "recovery_result_v2"',
        'result["version"] != 2',
        "result issued_at must be canonical UTC ISO-8601",
    ):
        assert marker in source

    for method_name, result_prefix in (
        ("_record_execution", "execution"),
        ("_record_verification_controlled", "verification"),
        ("_record_recovery", "recovery"),
    ):
        method_source = ast.get_source_segment(source, _method(method_name))
        assert "result" in {argument.arg for argument in _method(method_name).args.kwonlyargs}
        assert "result_digest" in {
            argument.arg for argument in _method(method_name).args.kwonlyargs
        }
        assert "self._canonical_result_envelope(" in method_source
        assert f'"{result_prefix}_result_json": encoded_result' in method_source
        assert f'"{result_prefix}_result_digest": result_digest' in method_source
        assert "self._is_same_result_replay(" in method_source
        assert method_source.index("self._is_same_result_replay(") < method_source.index(
            f'self.state != "{dict(execution="claimed", verification="committed", recovery="recovering")[result_prefix]}"'
        )

    bound_verification = ast.get_source_segment(source, _method("_record_verification"))
    root_verification = ast.get_source_segment(
        source, _method("_record_committed_verification_from_root")
    )
    controlled_verification = ast.get_source_segment(
        source, _method("_record_verification_controlled")
    )
    controlled_write = ast.get_source_segment(source, _method("_write_controlled"))
    assert "self._assert_bound_executor()" in bound_verification
    assert "root_verification=False" in bound_verification
    assert "if not self.env.su:" in root_verification
    assert "root_verification=True" in root_verification
    assert "root_verification=root_verification" in controlled_verification
    assert "self._ROOT_VERIFICATION_FIELDS" in controlled_write
    assert "not self.env.su" in controlled_write

    assert "prior_evidence_digest=None" in ast.get_source_segment(
        source, _method("_record_execution")
    )
    assert "prior_evidence_digest=self.execution_evidence_digest" in ast.get_source_segment(
        source, _method("_record_verification_controlled")
    )
    assert "prior_evidence_digest=self.recovery_plan_digest" in ast.get_source_segment(
        source, _method("_record_recovery")
    )

    failure_method = _method("_record_failure")
    failure_source = ast.get_source_segment(source, failure_method)
    assert {"result", "result_digest"} <= {
        argument.arg for argument in failure_method.args.kwonlyargs
    }
    assert "return self._record_execution(" in failure_source
    assert "return self._record_verification(" in failure_source
    assert "succeeded=False" in failure_source
    assert "passed=False" in failure_source
    assert "and not self.recovery_result_digest" in failure_source

    replay_source = ast.get_source_segment(source, _method("_is_same_result_replay"))
    controlled_write = ast.get_source_segment(source, _method("_write_controlled"))
    assert "if not any(stored):" in replay_source
    assert "if stored != expected:" in replay_source
    assert "return True" in replay_source
    assert "set(values) & self._RESULT_STORAGE_FIELDS" in controlled_write
    assert "self[field_name] != values[field_name]" in controlled_write

    assert "hmac" not in source
    assert "secret" not in source.lower()
    assert "signature =" not in source


def test_recovery_plan_is_idempotent_and_result_bound_after_first_write():
    source = _source()
    begin_recovery = ast.get_source_segment(source, _method("_begin_recovery"))
    controlled_write = ast.get_source_segment(source, _method("_write_controlled"))

    assert "if self.recovery_plan_digest:" in begin_recovery
    assert "recovery plan is immutable" in begin_recovery
    assert "return True" in begin_recovery
    assert "self.recovery_result_digest" in controlled_write
    assert "recovery_plan_json" in controlled_write
    assert "recovery_plan_digest" in controlled_write


def test_odoo_19_security_uses_privileges_and_company_record_rules():
    security = ET.parse(SECURITY)
    records_list = [
        record for record in security.getroot().iter("record") if "id" in record.attrib
    ]
    records = {record.attrib["id"]: record for record in records_list}

    assert len(records) == len(records_list)
    assert set(records) == {
        "module_category_odoo_accounting_cli_v3",
        "privilege_odoo_accounting_cli_v3",
        "group_executor",
        "group_approver",
        "operation_executor_company_rule",
        "operation_approver_company_rule",
        "approval_wizard_approver_company_rule",
    }
    privilege = records["privilege_odoo_accounting_cli_v3"]
    assert privilege.attrib["model"] == "res.groups.privilege"
    assert _record_fields(privilege)["category_id"].attrib["ref"] == (
        "module_category_odoo_accounting_cli_v3"
    )

    executor_fields = _record_fields(records["group_executor"])
    approver_fields = _record_fields(records["group_approver"])
    for fields in (executor_fields, approver_fields):
        assert fields["privilege_id"].attrib["ref"] == (
            "privilege_odoo_accounting_cli_v3"
        )
        assert "category_id" not in fields
    assert "account.group_account_user" in executor_fields["implied_ids"].attrib["eval"]
    assert "base.group_user" in approver_fields["implied_ids"].attrib["eval"]
    assert "account.group_account_manager" not in SECURITY.read_text(encoding="utf-8")

    for record_id, group_ref in (
        ("operation_executor_company_rule", "group_executor"),
        ("operation_approver_company_rule", "group_approver"),
    ):
        rule = records[record_id]
        fields = _record_fields(rule)
        assert rule.attrib["model"] == "ir.rule"
        assert fields["model_id"].attrib["ref"] == (
            "model_odoo_accounting_cli_operation"
        )
        assert f"ref('{group_ref}')" in fields["groups"].attrib["eval"]
        assert (fields["domain_force"].text or "").strip() == (
            "[('company_id', 'in', company_ids)]"
        )

    wizard_rule = records["approval_wizard_approver_company_rule"]
    wizard_fields = _record_fields(wizard_rule)
    assert wizard_rule.attrib["model"] == "ir.rule"
    assert wizard_fields["model_id"].attrib["ref"] == (
        "model_odoo_accounting_cli_v3_approval_wizard"
    )
    assert "ref('group_approver')" in wizard_fields["groups"].attrib["eval"]
    assert (wizard_fields["domain_force"].text or "").strip() == (
        "[('create_uid', '=', user.id), ('company_id', 'in', company_ids)]"
    )
    assert {
        name: wizard_fields[name].attrib["eval"]
        for name in ("perm_read", "perm_write", "perm_create", "perm_unlink")
    } == {
        "perm_read": "True",
        "perm_write": "True",
        "perm_create": "True",
        "perm_unlink": "False",
    }


def test_access_csv_is_least_privilege_and_has_no_unscoped_rows():
    with ACL.open(encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream)
        rows = list(reader)

    assert reader.fieldnames == [
        "id",
        "name",
        "model_id:id",
        "group_id:id",
        "perm_read",
        "perm_write",
        "perm_create",
        "perm_unlink",
    ]
    assert {row["id"] for row in rows} == {
        "access_operation_executor",
        "access_operation_approver",
        "access_approval_wizard_approver",
    }
    executor = next(row for row in rows if row["id"] == "access_operation_executor")
    approver = next(row for row in rows if row["id"] == "access_operation_approver")
    wizard = next(
        row for row in rows if row["id"] == "access_approval_wizard_approver"
    )
    assert executor["model_id:id"] == "model_odoo_accounting_cli_operation"
    assert approver["model_id:id"] == "model_odoo_accounting_cli_operation"
    assert wizard["model_id:id"] == (
        "model_odoo_accounting_cli_v3_approval_wizard"
    )
    assert executor["group_id:id"] == (
        "odoo_accounting_cli_v3_control.group_executor"
    )
    assert approver["group_id:id"] == (
        "odoo_accounting_cli_v3_control.group_approver"
    )
    assert wizard["group_id:id"] == (
        "odoo_accounting_cli_v3_control.group_approver"
    )
    assert [executor[f"perm_{name}"] for name in ("read", "write", "create", "unlink")] == [
        "1",
        "1",
        "1",
        "0",
    ]
    assert [approver[f"perm_{name}"] for name in ("read", "write", "create", "unlink")] == [
        "1",
        "0",
        "0",
        "0",
    ]
    assert [wizard[f"perm_{name}"] for name in ("read", "write", "create", "unlink")] == [
        "1",
        "1",
        "1",
        "0",
    ]
