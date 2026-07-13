import unittest

from odoo_accounting_cli_v3.odoo.trial_balance import OdooTrialBalanceBackend


class Company:
    id = 7

    def __bool__(self):
        return True

    def __len__(self):
        return 1

    def exists(self):
        return self

    def check_access_rights(self, operation):
        if operation != "read":
            raise AssertionError("unexpected access operation")

    def check_access_rule(self, operation):
        if operation != "read":
            raise AssertionError("unexpected record-rule operation")


class CompanyModel:
    def browse(self, company_id):
        if company_id != 7:
            raise AssertionError("unexpected company")
        return Company()


class Account:
    id = 401
    code = "1000"
    name = "Archived cash"
    account_type = "asset_cash"

    def with_company(self, company):
        if company.id != 7:
            raise AssertionError("unexpected company binding")
        return self


class AccountModel:
    def __init__(self):
        self.contexts = []
        self.domain = None

    def with_context(self, **context):
        self.contexts.append(context)
        return self

    def with_company(self, company):
        if company.id != 7:
            raise AssertionError("unexpected company binding")
        return self

    def search(self, domain, order):
        self.domain = domain
        if order != "code, id":
            raise AssertionError("unexpected ordering")
        return [Account()]


class Environment:
    uid = 42
    su = False

    def __init__(self):
        self.accounts = AccountModel()

    def __getitem__(self, model_name):
        if model_name == "res.company":
            return CompanyModel()
        if model_name == "account.account":
            return self.accounts
        raise AssertionError(f"unexpected model: {model_name}")


class OdooTrialBalanceBackendTest(unittest.TestCase):
    def test_account_catalog_includes_archived_accounts_with_posted_history(self):
        env = Environment()
        backend = OdooTrialBalanceBackend(
            env,
            user_id=42,
            allowed_company_ids=frozenset({7}),
        )

        accounts = backend.accounts(company_id=7, account_ids=None)

        self.assertEqual([item.id for item in accounts], [401])
        self.assertIn({"allowed_company_ids": [7]}, env.accounts.contexts)
        self.assertIn({"active_test": False}, env.accounts.contexts)
        self.assertEqual(env.accounts.domain, [("company_ids", "in", [7])])


if __name__ == "__main__":
    unittest.main()
