from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = PROJECT_ROOT / "src"
PACKAGE_NAME = "odoo_accounting_cli_v3"
FORBIDDEN_LOCAL_IMPORT_SUFFIXES = frozenset(
    {".bundle", ".dll", ".dylib", ".pyc", ".pyd", ".pyo", ".pyw", ".so"}
)
READ_GRAPH_ROOT_MODULES = frozenset(
    {"odoo_accounting_cli_v3.odoo.bootstrap"}
)
TRUSTED_READ_HANDLER_MODULES = frozenset(
    {
        "odoo_accounting_cli_v3.odoo.bootstrap",
        "odoo_accounting_cli_v3.odoo.executor",
        "odoo_accounting_cli_v3.odoo.ap_open_items",
        "odoo_accounting_cli_v3.odoo.ar_open_items",
        "odoo_accounting_cli_v3.odoo.multicurrency_balance",
        "odoo_accounting_cli_v3.odoo.trial_balance",
        "odoo_accounting_cli_v3.domain.ap_open_items",
        "odoo_accounting_cli_v3.domain.ar_open_items",
        "odoo_accounting_cli_v3.domain.multicurrency_balance",
        "odoo_accounting_cli_v3.domain.trial_balance",
    }
)
READ_TRANSACTION_MODULE = "odoo_accounting_cli_v3.odoo.read_transaction"
REVIEWED_READ_IMPORT_CLOSURE = frozenset(
    {
        "odoo_accounting_cli_v3",
        "odoo_accounting_cli_v3.auth",
        "odoo_accounting_cli_v3.contracts",
        "odoo_accounting_cli_v3.domain",
        "odoo_accounting_cli_v3.domain.ap_open_items",
        "odoo_accounting_cli_v3.domain.ar_open_items",
        "odoo_accounting_cli_v3.domain.multicurrency_balance",
        "odoo_accounting_cli_v3.domain.trial_balance",
        "odoo_accounting_cli_v3.domain.write_semantics",
        "odoo_accounting_cli_v3.gateway",
        "odoo_accounting_cli_v3.odoo",
        "odoo_accounting_cli_v3.odoo.ap_open_items",
        "odoo_accounting_cli_v3.odoo.ar_open_items",
        "odoo_accounting_cli_v3.odoo.bootstrap",
        "odoo_accounting_cli_v3.odoo.executor",
        "odoo_accounting_cli_v3.odoo.multicurrency_balance",
        "odoo_accounting_cli_v3.odoo.read_transaction",
        "odoo_accounting_cli_v3.odoo.trial_balance",
        "odoo_accounting_cli_v3.operations",
        "odoo_accounting_cli_v3.receipts",
        "odoo_accounting_cli_v3.registry",
    }
)
REVIEWED_EXTERNAL_IMPORTS = frozenset(
    {
        ("__future__", "annotations"),
        ("collections.abc", "Callable"),
        ("collections.abc", "Sequence"),
        ("dataclasses", "dataclass"),
        ("dataclasses", "replace"),
        ("datetime", "date"),
        ("datetime", "datetime"),
        ("datetime", "timedelta"),
        ("datetime", "timezone"),
        ("decimal", "Decimal"),
        ("decimal", "InvalidOperation"),
        ("decimal", "ROUND_HALF_UP"),
        ("enum", "StrEnum"),
        ("hashlib", None),
        ("hmac", None),
        ("importlib.metadata", "PackageNotFoundError"),
        ("importlib.metadata", "version"),
        ("json", None),
        ("math", None),
        ("odoo.api", "Environment"),
        ("pathlib", "Path"),
        ("re", None),
        ("secrets", None),
        ("typing", "Any"),
        ("typing", "Callable"),
        ("typing", "Iterable"),
        ("typing", "Mapping"),
        ("typing", "Protocol"),
        ("typing", "TypeVar"),
        ("uuid", None),
    }
)
REVIEWED_EXTERNAL_IMPORT_BINDINGS_SHA256 = (
    "c0cef62853689e885def29d1c48c76ae052541e13ce4e044b1b64081ed5b04c2"
)
REVIEWED_EXPLICIT_IMPORT_BINDINGS_SHA256 = (
    "38d40d9da592ee14020966c5b69e828d9477934e6a32e99e93ffdc32f43e14aa"
)
REVIEWED_READ_DISPATCH = {
    "acct.registry.list.v1": "_read_registry",
    "acct.gl.trial_balance.v1": "_read_trial_balance",
    "acct.ar.open_items.v1": "_read_ar_open_items",
    "acct.ap.open_items.v1": "_read_ap_open_items",
    "acct.multicurrency.balance_read.v1": "_read_multicurrency_balance",
    "acct.move.draft_cancel_eligibility.v1": "_read_draft_cancel_eligibility",
}
REVIEWED_ACTIVE_READ_CAPABILITIES = frozenset(REVIEWED_READ_DISPATCH)
READ_TRANSACTION_SOURCE_SHA256 = (
    "c34c536c0bf335cced59546aac4c5873c83acd90d34cf77757fc379e6667e016"
)
READ_BOOTSTRAP_SOURCE_SHA256 = (
    "6ac313f7406873448a83c07b405610d6e91e0d973e7e45eb8083bad1f02b40be"
)
READ_EXECUTOR_SOURCE_SHA256 = (
    "9fc8cdec7e58295948b23b3915abf8c3b1e9df2b7aa4c28a5bad77276659fec2"
)
REVIEWED_INITIALIZER_ATTRIBUTES = {
    ("odoo_accounting_cli_v3.gateway", "CapabilityGateway"): frozenset(
        {
            "_capabilities",
            "_registry_digest",
            "_release_digest",
            "_authenticate_context",
            "_acl_check",
            "_availability_channel",
            "_read_executor",
            "_read_receipt_verifier",
            "_operations",
            "_idempotency",
        }
    ),
    (
        "odoo_accounting_cli_v3.odoo.ar_open_items",
        "OdooArOpenItemsBackend",
    ): frozenset({"_env", "_user_id", "_allowed_company_ids"}),
    ("odoo_accounting_cli_v3.odoo.executor", "OdooReadExecutor"): frozenset(
        {
            "_env",
            "_capabilities",
            "_capability_map",
            "_odoo_instance_id",
            "_database_name",
            "_database_uuid",
            "_environment",
            "_capability_channel",
            "_receipt_secret",
            "_receipt_key_id",
            "_consume_receipt",
            "_now",
            "_receipt_id_factory",
            "_trial_balance_backend_factory",
            "_ar_open_items_backend_factory",
            "_ap_open_items_backend_factory",
            "_multicurrency_balance_backend_factory",
        }
    ),
    (
        "odoo_accounting_cli_v3.odoo.multicurrency_balance",
        "OdooMulticurrencyBalanceBackend",
    ): frozenset({"_env", "_user_id", "_allowed_company_ids"}),
    (
        "odoo_accounting_cli_v3.odoo.trial_balance",
        "OdooTrialBalanceBackend",
    ): frozenset({"_env", "_user_id", "_allowed_company_ids"}),
}
REVIEWED_SUBSCRIPT_MUTATIONS = frozenset(
    {
        (
            "odoo_accounting_cli_v3.domain.write_semantics",
            "_validate_draft_cancel",
            "computed",
        ),
        ("odoo_accounting_cli_v3.gateway", "prepare", "self._operations"),
        ("odoo_accounting_cli_v3.gateway", "prepare", "self._idempotency"),
        (
            "odoo_accounting_cli_v3.odoo.ar_open_items",
            "partials_as_of",
            "result",
        ),
        (
            "odoo_accounting_cli_v3.odoo.bootstrap",
            "_reject_duplicate_keys",
            "result",
        ),
        (
            "odoo_accounting_cli_v3.odoo.trial_balance",
            "_aggregate",
            "result",
        ),
        (
            "odoo_accounting_cli_v3.operations",
            "_operation_state_digest",
            "state",
        ),
        (
            "odoo_accounting_cli_v3.registry",
            "validate_registry",
            "evidence_receipt_ids",
        ),
    }
)
REVIEWED_COPY_CALLS = frozenset(
    {
        (
            "odoo_accounting_cli_v3.gateway",
            "list_capabilities",
            "capability.data",
        ),
        (
            "odoo_accounting_cli_v3.gateway",
            "get_capability",
            "self._authorized(context, capability_id).data",
        ),
        (
            "odoo_accounting_cli_v3.gateway",
            "preview",
            "capability.data['approval']",
        ),
        (
            "odoo_accounting_cli_v3.gateway",
            "preview",
            "capability.data['recovery']",
        ),
    }
)
REVIEWED_SOURCE_VIOLATIONS = frozenset(
    {
        ("odoo_accounting_cli_v3.odoo.ar_open_items", 18, "attribute:__class__"),
        (
            "odoo_accounting_cli_v3.odoo.multicurrency_balance",
            22,
            "attribute:__class__",
        ),
        ("odoo_accounting_cli_v3.odoo.trial_balance", 13, "attribute:__class__"),
    }
)
CRITICAL_IMMUTABLE_BINDINGS = {
    "odoo_accounting_cli_v3.odoo.bootstrap": frozenset(
        {"OdooReadExecutor", "run_readonly_odoo_transaction"}
    ),
    "odoo_accounting_cli_v3.odoo.executor": frozenset({"OdooReadExecutor"}),
    "odoo_accounting_cli_v3.odoo.read_transaction": frozenset(
        {"run_readonly_odoo_transaction"}
    ),
}
FORBIDDEN_ATTRIBUTES = frozenset(
    {
        "_write",
        "_create",
        "_unlink",
        "__class__",
        "__dict__",
        "__getattribute__",
        "__set__",
        "__setitem__",
        "_create_payments",
        "_generate_deferred_entries",
        "_post",
        "_reverse_moves",
        "action_cancel",
        "action_confirm",
        "action_create_payments",
        "action_draft",
        "action_post",
        "action_validate",
        "button_draft",
        "button_cancel",
        "button_validate",
        "callproc",
        "commit",
        "compute_depreciation_board",
        "create",
        "cursor",
        "execute",
        "executemany",
        "flush",
        "flush_all",
        "flush_model",
        "flush_recordset",
        "invalidate_all",
        "invalidate_model",
        "invalidate_recordset",
        "modified",
        "name_create",
        "reconcile",
        "remove_move_reconcile",
        "reset",
        "reverse_moves",
        "rollback",
        "savepoint",
        "set_isolation_level",
        "set_session",
        "sudo",
        "toggle_active",
        "tpc_begin",
        "tpc_commit",
        "tpc_prepare",
        "tpc_rollback",
        "unlink",
        "write_bytes",
        "write_text",
        "touch",
        "mkdir",
        "rmdir",
        "rename",
        "link_to",
        "symlink_to",
        "hardlink_to",
        "chmod",
        "lchmod",
        "chown",
        "popen",
        "system",
        "with_env",
        "with_user",
        "write",
        "update",
    }
)
FORBIDDEN_FUNCTION_CALLS = frozenset(
    {
        "__import__",
        "compile",
        "delattr",
        "eval",
        "exec",
        "open",
        "setattr",
        "vars",
        "globals",
        "locals",
    }
)
FORBIDDEN_IMPORT_PREFIXES = (
    "asyncpg",
    "odoo.sql_db",
    "psycopg",
    "psycopg2",
    "odoo_accounting_cli_v3.effect_finalizer",
    "odoo_accounting_cli_v3.odoo.module_guard",
    "odoo_accounting_cli_v3.odoo.write_",
    "odoo_accounting_cli_v3.write_",
)
FORBIDDEN_RELATIVE_IMPORT_PREFIXES = (
    "effect_finalizer",
    "module_guard",
    "write_",
)
FORBIDDEN_IMPORT_ROOTS = frozenset(
    {
        "ftplib",
        "http",
        "httpx",
        "requests",
        "smtplib",
        "socket",
        "subprocess",
        "urllib",
    }
)


def _select_module_source(
    module_name: str, file_candidate: Path, package_candidate: Path
) -> Path | None:
    file_exists = file_candidate.is_file()
    package_exists = package_candidate.is_file()
    assert not (file_exists and package_exists), (
        f"ambiguous module/package source is forbidden: {module_name}"
    )
    if package_exists:
        return package_candidate
    return file_candidate if file_exists else None


def _module_path(module_name: str) -> Path | None:
    if module_name == PACKAGE_NAME:
        candidate = SOURCE_ROOT / PACKAGE_NAME / "__init__.py"
    elif module_name.startswith(f"{PACKAGE_NAME}."):
        relative = module_name.removeprefix(f"{PACKAGE_NAME}.")
        candidate = SOURCE_ROOT / PACKAGE_NAME / Path(*relative.split("."))
        file_candidate = candidate.with_suffix(".py")
        package_candidate = candidate / "__init__.py"
        return _select_module_source(
            module_name, file_candidate, package_candidate
        )
    else:
        return None
    return candidate if candidate.is_file() else None


def _resolve_import_from(module_name: str, node: ast.ImportFrom) -> str:
    if node.level == 0:
        return node.module or ""
    path = _module_path(module_name)
    assert path is not None, f"reviewed module is absent: {module_name}"
    package = (
        module_name
        if path.name == "__init__.py"
        else module_name.rpartition(".")[0]
    )
    relative_name = f"{'.' * node.level}{node.module or ''}"
    return importlib.util.resolve_name(relative_name, package)


def _parent_package_modules(module_name: str) -> set[str]:
    parts = module_name.split(".")
    parents = set()
    for size in range(1, len(parts)):
        candidate = ".".join(parts[:size])
        path = _module_path(candidate)
        if path is not None and path.name == "__init__.py":
            parents.add(candidate)
    return parents


def _imports_for_module(
    module_name: str,
) -> tuple[
    set[str],
    set[tuple[str, str | None]],
    set[tuple[str, str | None, str | None]],
]:
    path = _module_path(module_name)
    assert path is not None, f"reviewed module is absent: {module_name}"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    internal: set[str] = set()
    external_imports: set[tuple[str, str | None]] = set()
    explicit_imports: set[tuple[str, str | None, str | None]] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                explicit_imports.add((alias.name, None, alias.asname))
                if alias.name == PACKAGE_NAME or alias.name.startswith(
                    f"{PACKAGE_NAME}."
                ):
                    if _module_path(alias.name):
                        internal.add(alias.name)
                else:
                    external_imports.add((alias.name, None))
        elif isinstance(node, ast.ImportFrom):
            base = _resolve_import_from(module_name, node)
            explicit_imports.update(
                (base, alias.name, alias.asname) for alias in node.names
            )
            if base == PACKAGE_NAME or base.startswith(
                f"{PACKAGE_NAME}."
            ):
                if base != PACKAGE_NAME and _module_path(base):
                    internal.add(base)
                for alias in node.names:
                    candidate = f"{base}.{alias.name}"
                    if _module_path(candidate):
                        internal.add(candidate)
            else:
                external_imports.update((base, alias.name) for alias in node.names)
    return internal, external_imports, explicit_imports


def _read_import_closure() -> tuple[
    set[str],
    set[tuple[str, str, str | None]],
    set[tuple[str, str, str | None, str | None]],
]:
    pending = list(READ_GRAPH_ROOT_MODULES)
    observed: set[str] = set()
    external_import_bindings: set[tuple[str, str, str | None]] = set()
    explicit_import_bindings: set[
        tuple[str, str, str | None, str | None]
    ] = set()
    while pending:
        module_name = pending.pop()
        if module_name in observed:
            continue
        observed.add(module_name)
        internal, external, explicit = _imports_for_module(module_name)
        pending.extend(sorted(_parent_package_modules(module_name) - observed))
        pending.extend(sorted(internal - observed))
        external_import_bindings.update(
            (module_name, imported_module, imported_symbol)
            for imported_module, imported_symbol in external
        )
        explicit_import_bindings.update(
            (module_name, imported_module, imported_symbol, local_alias)
            for imported_module, imported_symbol, local_alias in explicit
        )
    return observed, external_import_bindings, explicit_import_bindings


def _import_binding_digest(
    bindings: set[tuple[str | None, ...]],
) -> str:
    rows = sorted(
        (list(binding) for binding in bindings),
        key=lambda row: tuple("" if value is None else value for value in row),
    )
    payload = json.dumps(
        rows,
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _executor_dispatch_contract() -> dict[str, str]:
    path = _module_path("odoo_accounting_cli_v3.odoo.executor")
    assert path is not None
    assert hashlib.sha256(path.read_bytes()).hexdigest() == (
        READ_EXECUTOR_SOURCE_SHA256
    )
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    executor_classes = [
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "OdooReadExecutor"
    ]
    assert len(executor_classes) == 1
    executor_class = executor_classes[0]
    assert executor_class.decorator_list == []
    assert executor_class.bases == []
    assert executor_class.keywords == []
    methods = {
        node.name: node
        for node in executor_class.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    handler_method = methods.get("_read_handlers")
    call_method = methods.get("__call__")
    assert isinstance(handler_method, ast.FunctionDef)
    assert isinstance(call_method, ast.FunctionDef)
    assert handler_method.decorator_list == []
    assert call_method.decorator_list == []
    returns = [node for node in ast.walk(handler_method) if isinstance(node, ast.Return)]
    assert len(returns) == 1 and isinstance(returns[0].value, ast.Dict)
    table = returns[0].value
    assert len(table.keys) == len(table.values)
    dispatch: dict[str, str] = {}
    for key, value in zip(table.keys, table.values, strict=True):
        assert isinstance(key, ast.Constant) and isinstance(key.value, str)
        assert (
            isinstance(value, ast.Attribute)
            and isinstance(value.value, ast.Name)
            and value.value.id == "self"
        )
        assert key.value not in dispatch
        assert value.attr in methods
        dispatch[key.value] = value.attr

    allowlist_assignments = [
        node
        for node in tree.body
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == "_CAPABILITIES"
    ]
    assert len(allowlist_assignments) == 1
    allowlist_call = allowlist_assignments[0].value
    assert (
        isinstance(allowlist_call, ast.Call)
        and isinstance(allowlist_call.func, ast.Name)
        and allowlist_call.func.id == "frozenset"
        and len(allowlist_call.args) == 1
        and not allowlist_call.keywords
        and isinstance(allowlist_call.args[0], ast.Set)
    )
    allowlist = {
        item.value
        for item in allowlist_call.args[0].elts
        if isinstance(item, ast.Constant) and isinstance(item.value, str)
    }
    assert len(allowlist) == len(allowlist_call.args[0].elts)
    assert allowlist == set(dispatch)

    handler_assignments = [
        node
        for node in ast.walk(call_method)
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == "handler"
    ]
    assert len(handler_assignments) == 1
    selector = handler_assignments[0].value
    assert (
        isinstance(selector, ast.Call)
        and isinstance(selector.func, ast.Attribute)
        and selector.func.attr == "get"
        and isinstance(selector.func.value, ast.Call)
        and isinstance(selector.func.value.func, ast.Attribute)
        and isinstance(selector.func.value.func.value, ast.Name)
        and selector.func.value.func.value.id == "self"
        and selector.func.value.func.attr == "_read_handlers"
        and selector.func.value.args == []
        and len(selector.args) == 1
        and isinstance(selector.args[0], ast.Attribute)
        and isinstance(selector.args[0].value, ast.Name)
        and selector.args[0].value.id == "capability"
        and selector.args[0].attr == "id"
    )
    body_assignments = [
        node
        for node in ast.walk(call_method)
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == "body"
    ]
    assert len(body_assignments) == 1
    invocation = body_assignments[0].value
    assert (
        isinstance(invocation, ast.Call)
        and isinstance(invocation.func, ast.Name)
        and invocation.func.id == "handler"
        and [argument.id for argument in invocation.args if isinstance(argument, ast.Name)]
        == ["context", "parameters"]
        and len(invocation.args) == 2
        and invocation.keywords == []
    )
    return dispatch


def _forbidden_attribute(name: str) -> bool:
    return (
        name in FORBIDDEN_ATTRIBUTES
        or name.startswith("action_")
        or name.startswith("button_")
    )


def _nearest_ancestor(
    node: ast.AST,
    parents: dict[ast.AST, ast.AST],
    accepted: type[ast.AST] | tuple[type[ast.AST], ...],
) -> ast.AST | None:
    current = node
    while current in parents:
        current = parents[current]
        if isinstance(current, accepted):
            return current
    return None


def _plain_dict_expression(node: ast.AST | None) -> bool:
    return isinstance(node, (ast.Dict, ast.DictComp))


def _store_binding_value(
    store: ast.Attribute | ast.Name,
    parents: dict[ast.AST, ast.AST],
) -> ast.AST | None:
    parent = parents.get(store)
    if isinstance(parent, ast.Assign) and any(
        target is store for target in parent.targets
    ):
        return parent.value
    if isinstance(parent, ast.AnnAssign) and parent.target is store:
        return parent.value
    if isinstance(parent, ast.NamedExpr) and parent.target is store:
        return parent.value
    return None


def _local_mapping_has_single_plain_dict_binding(
    mutation: ast.Subscript,
    name: str,
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    parents: dict[ast.AST, ast.AST],
) -> bool:
    stores = [
        candidate
        for candidate in ast.walk(function)
        if isinstance(candidate, ast.Name)
        and candidate.id == name
        and isinstance(candidate.ctx, (ast.Store, ast.Del))
        and _nearest_ancestor(
            candidate, parents, (ast.FunctionDef, ast.AsyncFunctionDef)
        )
        is function
    ]
    return (
        len(stores) == 1
        and stores[0].lineno < mutation.lineno
        and _plain_dict_expression(_store_binding_value(stores[0], parents))
    )


def _instance_mapping_has_single_plain_dict_binding(
    mutation: ast.Subscript,
    attribute: str,
    owner: ast.ClassDef,
    parents: dict[ast.AST, ast.AST],
) -> bool:
    stores = [
        candidate
        for candidate in ast.walk(owner)
        if isinstance(candidate, ast.Attribute)
        and isinstance(candidate.ctx, (ast.Store, ast.Del))
        and isinstance(candidate.value, ast.Name)
        and candidate.value.id == "self"
        and candidate.attr == attribute
        and _nearest_ancestor(candidate, parents, ast.ClassDef) is owner
    ]
    if len(stores) != 1 or stores[0].lineno >= mutation.lineno:
        return False
    initializer = _nearest_ancestor(
        stores[0], parents, (ast.FunctionDef, ast.AsyncFunctionDef)
    )
    return (
        isinstance(initializer, (ast.FunctionDef, ast.AsyncFunctionDef))
        and initializer.name == "__init__"
        and initializer.decorator_list == []
        and _plain_dict_expression(_store_binding_value(stores[0], parents))
    )


def _reviewed_mutation_target(
    node: ast.Attribute | ast.Subscript,
    filename: str,
    parents: dict[ast.AST, ast.AST],
) -> bool:
    function = _nearest_ancestor(
        node, parents, (ast.FunctionDef, ast.AsyncFunctionDef)
    )
    if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return False
    if isinstance(node, ast.Attribute):
        owner = _nearest_ancestor(node, parents, ast.ClassDef)
        return (
            function.name == "__init__"
            and isinstance(owner, ast.ClassDef)
            and owner.decorator_list == []
            and owner.bases == []
            and owner.keywords == []
            and function.decorator_list == []
            and isinstance(node.value, ast.Name)
            and node.value.id == "self"
            and node.attr
            in REVIEWED_INITIALIZER_ATTRIBUTES.get((filename, owner.name), frozenset())
        )

    base = node.value
    if isinstance(base, ast.Name):
        base_name = base.id
        proven_plain_mapping = _local_mapping_has_single_plain_dict_binding(
            node, base_name, function, parents
        )
    elif (
        isinstance(base, ast.Attribute)
        and isinstance(base.value, ast.Name)
        and base.value.id == "self"
    ):
        base_name = f"self.{base.attr}"
        owner = _nearest_ancestor(node, parents, ast.ClassDef)
        proven_plain_mapping = (
            isinstance(owner, ast.ClassDef)
            and owner.decorator_list == []
            and owner.bases == []
            and owner.keywords == []
            and _instance_mapping_has_single_plain_dict_binding(
                node, base.attr, owner, parents
            )
        )
    else:
        return False
    return (
        proven_plain_mapping
        and (filename, function.name, base_name) in REVIEWED_SUBSCRIPT_MUTATIONS
    )


def _source_violations(source: str, filename: str) -> list[tuple[str, int, str]]:
    tree = ast.parse(source, filename=filename)
    parents = {
        child: parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }
    violations = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Name)
            and isinstance(node.ctx, (ast.Store, ast.Del))
            and node.id in CRITICAL_IMMUTABLE_BINDINGS.get(filename, frozenset())
        ):
            violations.append((filename, node.lineno, "binding:critical-rebind"))
        elif (
            isinstance(node, (ast.Attribute, ast.Subscript))
            and isinstance(node.ctx, (ast.Store, ast.Del))
            and not _reviewed_mutation_target(node, filename, parents)
        ):
            violations.append((filename, node.lineno, "mutation:assignment-target"))
        elif isinstance(node, ast.Call) and not isinstance(
            node.func, (ast.Name, ast.Attribute)
        ):
            violations.append((filename, node.lineno, "call:indirect-callee"))
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "open"
        ):
            positional_mode = node.args[0] if node.args else None
            keyword_modes = [
                keyword.value for keyword in node.keywords if keyword.arg == "mode"
            ]
            if len(keyword_modes) > 1 or (positional_mode is not None and keyword_modes):
                violations.append((filename, node.lineno, "call:open-mode"))
            else:
                mode = keyword_modes[0] if keyword_modes else positional_mode
                if mode is not None and (
                    not isinstance(mode, ast.Constant)
                    or mode.value not in {"r", "rt", "rb"}
                ):
                    violations.append((filename, node.lineno, "call:open-mode"))
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "replace"
        ):
            replacements = tuple(
                argument.value
                for argument in node.args
                if isinstance(argument, ast.Constant)
                and isinstance(argument.value, str)
            )
            if (
                len(node.args) != 2
                or replacements not in {("Z", "+00:00"), ("+00:00", "Z")}
                or node.keywords
            ):
                violations.append((filename, node.lineno, "call:replace"))
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "copy"
        ):
            function = _nearest_ancestor(
                node, parents, (ast.FunctionDef, ast.AsyncFunctionDef)
            )
            reviewed = (
                filename,
                function.name
                if isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef))
                else "",
                ast.unparse(node.func.value),
            )
            if node.args or node.keywords or reviewed not in REVIEWED_COPY_CALLS:
                violations.append((filename, node.lineno, "call:copy"))
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "load"
        ):
            function = _nearest_ancestor(
                node, parents, (ast.FunctionDef, ast.AsyncFunctionDef)
            )
            if not (
                filename == "odoo_accounting_cli_v3.registry"
                and isinstance(function, ast.FunctionDef)
                and function.name == "load_registry"
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "json"
                and len(node.args) == 1
                and isinstance(node.args[0], ast.Name)
                and node.args[0].id == "stream"
                and not node.keywords
            ):
                violations.append((filename, node.lineno, "call:load"))
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "__setattr__"
        ):
            if not (
                isinstance(node.func.value, ast.Name)
                and node.func.value.id == "object"
                and len(node.args) == 3
                and isinstance(node.args[0], ast.Name)
                and node.args[0].id == "self"
                and isinstance(node.args[1], ast.Constant)
                and node.args[1].value == "database_uuid"
                and node.keywords == []
            ):
                violations.append((filename, node.lineno, "call:__setattr__"))
        elif isinstance(node, ast.Attribute) and _forbidden_attribute(node.attr):
            violations.append((filename, node.lineno, f"attribute:{node.attr}"))
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            name = node.func.id
            if name in FORBIDDEN_FUNCTION_CALLS:
                violations.append((filename, node.lineno, f"call:{name}"))
            elif name == "getattr":
                attribute = node.args[1] if len(node.args) >= 2 else None
                if (
                    not isinstance(attribute, ast.Constant)
                    or not isinstance(attribute.value, str)
                    or _forbidden_attribute(attribute.value)
                ):
                    violations.append((filename, node.lineno, "dynamic:getattr"))
        elif isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".", 1)[0]
                if root in FORBIDDEN_IMPORT_ROOTS or alias.name.startswith(
                    FORBIDDEN_IMPORT_PREFIXES
                ):
                    violations.append((filename, node.lineno, f"import:{alias.name}"))
        elif isinstance(node, ast.ImportFrom):
            if any(alias.name == "*" for alias in node.names):
                violations.append((filename, node.lineno, "import:wildcard"))
            if node.level == 0 and node.module:
                root = node.module.split(".", 1)[0]
                imported_members = {
                    f"{node.module}.{alias.name}" for alias in node.names
                }
                if (
                    root in FORBIDDEN_IMPORT_ROOTS
                    or node.module.startswith(FORBIDDEN_IMPORT_PREFIXES)
                    or any(
                        member.startswith(FORBIDDEN_IMPORT_PREFIXES)
                        for member in imported_members
                    )
                ):
                    violations.append((filename, node.lineno, f"import:{node.module}"))
            elif node.level > 0 and node.module and node.module.startswith(
                FORBIDDEN_RELATIVE_IMPORT_PREFIXES
            ):
                violations.append((filename, node.lineno, f"import:{node.module}"))
    return violations


def test_policy_covers_every_staged_or_enabled_read_capability():
    document = json.loads(
        (PROJECT_ROOT / "registry/capabilities.json").read_text(encoding="utf-8")
    )
    active_reads = {
        capability["id"]
        for capability in document["capabilities"]
        if capability["access"] == "read"
        and (
            capability.get("staged_environments", [])
            or capability.get("enabled_environments", [])
        )
    }
    assert active_reads == set(REVIEWED_ACTIVE_READ_CAPABILITIES)
    assert _executor_dispatch_contract() == REVIEWED_READ_DISPATCH
    assert set(REVIEWED_READ_DISPATCH) == active_reads


def test_read_entrypoint_has_exact_reviewed_transitive_import_closure():
    (
        observed,
        external_import_bindings,
        explicit_import_bindings,
    ) = _read_import_closure()
    external_imports = {
        (imported_module, imported_symbol)
        for _, imported_module, imported_symbol in external_import_bindings
    }
    assert observed == set(REVIEWED_READ_IMPORT_CLOSURE)
    assert external_imports == set(REVIEWED_EXTERNAL_IMPORTS)
    assert len(external_import_bindings) == 134
    assert _import_binding_digest(external_import_bindings) == (
        REVIEWED_EXTERNAL_IMPORT_BINDINGS_SHA256
    )
    assert len(explicit_import_bindings) == 196
    assert _import_binding_digest(explicit_import_bindings) == (
        REVIEWED_EXPLICIT_IMPORT_BINDINGS_SHA256
    )
    assert TRUSTED_READ_HANDLER_MODULES < REVIEWED_READ_IMPORT_CLOSURE
    assert READ_TRANSACTION_MODULE in REVIEWED_READ_IMPORT_CLOSURE


def test_external_import_binding_cannot_move_between_reviewed_modules():
    _, bindings, _ = _read_import_closure()
    original = (
        "odoo_accounting_cli_v3",
        "pathlib",
        "Path",
    )
    moved = (
        "odoo_accounting_cli_v3.odoo.trial_balance",
        "pathlib",
        "Path",
    )
    modified = (bindings - {original}) | {moved}

    assert {
        (module, symbol) for _, module, symbol in modified
    } == {
        (module, symbol) for _, module, symbol in bindings
    }
    assert _import_binding_digest(modified) != (
        REVIEWED_EXTERNAL_IMPORT_BINDINGS_SHA256
    )


def test_relative_import_resolution_distinguishes_packages_from_modules():
    root_relative = ast.parse("from .contracts import validate_value").body[0]
    package_relative = ast.parse("from .executor import OdooReadExecutor").body[0]
    module_relative = ast.parse("from .executor import OdooReadExecutor").body[0]
    assert isinstance(root_relative, ast.ImportFrom)
    assert isinstance(package_relative, ast.ImportFrom)
    assert isinstance(module_relative, ast.ImportFrom)

    assert _resolve_import_from(PACKAGE_NAME, root_relative) == (
        "odoo_accounting_cli_v3.contracts"
    )
    assert _resolve_import_from("odoo_accounting_cli_v3.odoo", package_relative) == (
        "odoo_accounting_cli_v3.odoo.executor"
    )
    assert _resolve_import_from(
        "odoo_accounting_cli_v3.odoo.bootstrap", module_relative
    ) == "odoo_accounting_cli_v3.odoo.executor"


def test_module_resolution_rejects_file_package_ambiguity(tmp_path):
    file_candidate = tmp_path / "candidate.py"
    package_candidate = tmp_path / "candidate" / "__init__.py"
    package_candidate.parent.mkdir()
    file_candidate.write_text("safe = True\n", encoding="utf-8")
    package_candidate.write_text("unsafe = True\n", encoding="utf-8")

    with pytest.raises(AssertionError, match="ambiguous module/package"):
        _select_module_source(
            "odoo_accounting_cli_v3.candidate",
            file_candidate,
            package_candidate,
        )


def test_source_root_has_no_external_shadows_or_importable_binary_modules():
    unexpected_roots = [
        path.name
        for path in SOURCE_ROOT.iterdir()
        if path.name != PACKAGE_NAME
        and not (
            path.is_dir()
            and path.name.endswith((".egg-info", ".dist-info"))
        )
    ]
    package_root = SOURCE_ROOT / PACKAGE_NAME
    forbidden_importables = [
        path.relative_to(SOURCE_ROOT).as_posix()
        for path in package_root.rglob("*")
        if path.is_file()
        and path.suffix.lower() in FORBIDDEN_LOCAL_IMPORT_SUFFIXES
        and not (
            path.suffix.lower() in {".pyc", ".pyo"}
            and "__pycache__" in path.parts
        )
    ]

    assert unexpected_roots == []
    assert forbidden_importables == []


def test_trusted_read_handlers_have_no_write_escape_calls_or_network_imports():
    violations = []
    scanned_modules = REVIEWED_READ_IMPORT_CLOSURE - {READ_TRANSACTION_MODULE}
    for module_name in sorted(scanned_modules):
        path = _module_path(module_name)
        assert path is not None, f"trusted read dependency is absent: {module_name}"
        violations.extend(
            _source_violations(path.read_text(encoding="utf-8"), module_name)
        )

    assert set(violations) == set(REVIEWED_SOURCE_VIOLATIONS)


def test_bootstrap_source_and_public_read_boundary_are_pinned():
    path = _module_path("odoo_accounting_cli_v3.odoo.bootstrap")
    assert path is not None
    assert hashlib.sha256(path.read_bytes()).hexdigest() == (
        READ_BOOTSTRAP_SOURCE_SHA256
    )
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    functions = {
        node.name: node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    wrapper = functions["execute_read_from_odoo_shell"]
    json_wrapper = functions["execute_read_json"]
    assert wrapper.decorator_list == []
    assert json_wrapper.decorator_list == []
    boundary_calls = [
        node
        for node in ast.walk(wrapper)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "run_readonly_odoo_transaction"
    ]
    json_calls = [
        node
        for node in ast.walk(json_wrapper)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "execute_read_from_odoo_shell"
    ]
    assert len(boundary_calls) == 1
    assert len(json_calls) == 1


def test_transaction_hardening_module_has_exact_privileged_structure():
    path = _module_path(READ_TRANSACTION_MODULE)
    assert path is not None
    assert hashlib.sha256(path.read_bytes()).hexdigest() == (
        READ_TRANSACTION_SOURCE_SHA256
    )
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    imports = set()
    assignments = {}
    calls_by_attribute: dict[str, list[ast.Call]] = {}
    named_calls: list[str] = []
    indirect_calls: list[int] = []
    attribute_mutations = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module)
        elif (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and isinstance(node.value, ast.Constant)
        ):
            assignments[node.targets[0].id] = node.value.value
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            calls_by_attribute.setdefault(node.func.attr, []).append(node)
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            named_calls.append(node.func.id)
        elif isinstance(node, ast.Call):
            indirect_calls.append(node.lineno)
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.Delete)):
            targets = getattr(node, "targets", [getattr(node, "target", None)])
            if any(isinstance(target, (ast.Attribute, ast.Subscript)) for target in targets):
                attribute_mutations.append(node.lineno)

    assert imports == {"__future__", "secrets", "collections.abc", "typing"}
    assert set(named_calls) == {
        "OdooReadTransactionError",
        "TypeVar",
        "_begin_attested_transaction",
        "_require_attestation",
        "_require_cursor",
        "_require_readonly_session",
        "_require_transaction_status",
        "_verify_attested_transaction",
        "callable",
        "callback",
        "getattr",
        "isinstance",
        "len",
        "tuple",
    }
    assert named_calls.count("callback") == 1
    assert named_calls.count("getattr") == 4
    assert indirect_calls == []
    assert attribute_mutations == []
    assert assignments["_MARKER_SETTING"] == (
        "odoo_accounting_cli_v3.read_transaction_marker"
    )
    assert assignments["_BEGIN_ATTESTATION_SQL"] == (
        "SELECT current_setting('transaction_read_only'), "
        "current_setting('transaction_isolation'), set_config(%s, %s, true)"
    )
    assert assignments["_VERIFY_ATTESTATION_SQL"] == (
        "SELECT current_setting('transaction_read_only'), "
        "current_setting('transaction_isolation'), current_setting(%s, true)"
    )
    sql_values = {
        value
        for name, value in assignments.items()
        if name.endswith("_SQL")
    }
    assert len(sql_values) == 2
    assert all(value.startswith("SELECT ") and ";" not in value for value in sql_values)

    set_session_calls = calls_by_attribute.get("set_session", [])
    assert len(set_session_calls) == 1
    assert set_session_calls[0].args == []
    assert {
        keyword.arg: ast.literal_eval(keyword.value)
        for keyword in set_session_calls[0].keywords
    } == {"readonly": True, "isolation_level": "REPEATABLE READ"}

    execute_calls = calls_by_attribute.get("execute", [])
    assert set(calls_by_attribute) == {
        "execute",
        "fetchone",
        "get_transaction_status",
        "rollback",
        "set_session",
        "token_hex",
    }
    assert len(execute_calls) == 2
    assert {
        call.args[0].id
        for call in execute_calls
        if call.args and isinstance(call.args[0], ast.Name)
    } == {"_BEGIN_ATTESTATION_SQL", "_VERIFY_ATTESTATION_SQL"}
    assert len(calls_by_attribute.get("fetchone", [])) == 2

    rollback_calls = calls_by_attribute.get("rollback", [])
    assert len(rollback_calls) == 1
    finalbody_nodes = {
        id(descendant)
        for candidate in ast.walk(tree)
        if isinstance(candidate, ast.Try)
        for statement in candidate.finalbody
        for descendant in ast.walk(statement)
    }
    assert id(rollback_calls[0]) in finalbody_nodes
    assert {
        "set_session",
        "execute",
        "fetchone",
        "rollback",
        "get_transaction_status",
    }.issubset(calls_by_attribute)


@pytest.mark.parametrize(
    "source",
    [
        "record.create({})",
        "fn = record.write\nfn({})",
        "record.unlink()",
        "env.cr.execute('SELECT 1')",
        "env.cr.commit()",
        "env.sudo()",
        "move.action_post()",
        "lines.reconcile()",
        "setattr(record, 'name', value)",
        "getattr(record, 'write')({})",
        "from .write_handlers import OdooWriteHandler",
        "from ..write_service import execute_write",
        "Path('x').write_text('unsafe')",
        "Path('x').open('w')",
        "Path('x').open(mode='a')",
        "Path('x').replace('other')",
        "Path('x').link_to('other')",
        "os.system('unsafe')",
        "__import__('socket')",
        "record.__getattribute__('write')({})",
        "record.__setattr__('name', value)",
        "object.__setattr__(record, 'name', value)",
        "record.__setitem__('name', value)",
        "record._fields['name'].__set__(record, value)",
        "record.copy({'name': value})",
        "record.name_create('unsafe')",
        "record.load(['name'], [['unsafe']])",
        "vars(record)['write']({})",
        "from odoo import sql_db",
        "(cursor.commit,)[0]()",
        "(connection.set_session,)[0](readonly=False)",
        "cursor.__class__.__dict__['execute'](cursor, statement)",
        "record.name = 'unsafe'",
        "record['name'] = 'unsafe'",
        "del record.name",
    ],
)
def test_static_policy_rejects_known_write_escapes(source):
    assert _source_violations(source, "negative.py")


def test_reviewed_local_mapping_name_cannot_be_rebound_to_an_odoo_record():
    source = """
class OdooArOpenItemsBackend:
    def partials_as_of(self):
        result = {}
        result = self._env['res.partner'].browse(1)
        result['name'] = 'unsafe'
"""
    violations = _source_violations(
        source,
        "odoo_accounting_cli_v3.odoo.ar_open_items",
    )
    assert any(item[2] == "mutation:assignment-target" for item in violations)


def test_plain_dict_provenance_rejects_shadowed_dict_constructor():
    source = """
class OdooArOpenItemsBackend:
    def partials_as_of(self):
        dict = lambda: self._env['res.partner'].browse(1)
        result = dict()
        result['name'] = 'unsafe'
"""
    violations = _source_violations(
        source,
        "odoo_accounting_cli_v3.odoo.ar_open_items",
    )
    assert any(item[2] == "mutation:assignment-target" for item in violations)


def test_critical_read_boundary_binding_cannot_be_reassigned():
    source = """
_original = run_readonly_odoo_transaction
def _wrapper(root_env, callback):
    return callback()
run_readonly_odoo_transaction = _wrapper
"""
    violations = _source_violations(
        source,
        "odoo_accounting_cli_v3.odoo.bootstrap",
    )
    assert any(item[2] == "binding:critical-rebind" for item in violations)


def test_static_policy_allows_reviewed_read_operations():
    source = """
records = model.with_context(active_test=False).with_company(company).search([])
records.check_access_rights('read')
records.check_access_rule('read')
rows = records._read_group([], ['company_id'], ['balance:sum'])
rate = currency._get_conversion_rate(source, target, company, date)
with path.open(encoding='utf-8') as stream:
    payload = stream.read()
"""
    assert _source_violations(source, "positive.py") == []
