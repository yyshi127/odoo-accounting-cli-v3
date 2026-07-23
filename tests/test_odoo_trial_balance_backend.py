import unittest

from odoo_accounting_cli_v3.domain.trial_balance import TrialBalanceError
from odoo_accounting_cli_v3.odoo.trial_balance import OdooTrialBalanceBackend


class AccessError(Exception):
    pass


class Company:
    id = 7

    def exists(self):
        return self

    def __bool__(self):
        return True

    def __len__(self):
        return 1

    def check_access_rights(self, operation):
        if operation != "read":
            raise AssertionError("unexpected operation")

    def check_access_rule(self, operation):
        if operation != "read":
            raise AssertionError("unexpected operation")
        raise AccessError("hidden company")


class CompanyModel:
    def __init__(self, company):
        self.company = company

    def browse(self, company_id):
        if company_id != self.company.id:
            raise AssertionError("unexpected company")
        return self.company


class BoundModel:
    def with_context(self, **_context):
        return self

    def with_company(self, _company):
        return self

    def check_access_rights(self, operation):
        if operation != "read":
            raise AssertionError("unexpected operation")


class Environment:
    su = False
    uid = 42

    def __init__(self):
        self.company = Company()

    def __getitem__(self, model_name):
        if model_name == "res.company":
            return CompanyModel(self.company)
        return BoundModel()


class OdooTrialBalanceBackendTest(unittest.TestCase):
    def test_company_access_error_is_reported_as_company_visibility(self):
        backend = OdooTrialBalanceBackend(
            Environment(),
            user_id=42,
            allowed_company_ids=frozenset({7}),
        )

        with self.assertRaisesRegex(TrialBalanceError, "company does not exist"):
            backend.assert_read_access(company_id=7)


if __name__ == "__main__":
    unittest.main()
