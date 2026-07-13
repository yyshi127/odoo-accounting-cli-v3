import math
import unittest

from odoo_accounting_cli_v3.contracts import ContractError, validate_value


class ContractTest(unittest.TestCase):
    def test_pattern_and_length_are_enforced(self) -> None:
        schema = {"type": "string", "pattern": r"^-?[0-9]+\.[0-9]{2}$", "minLength": 4, "maxLength": 20}
        validate_value("100.00", schema)
        with self.assertRaisesRegex(ContractError, "pattern"):
            validate_value("one hundred", schema)

    def test_timezone_is_required_for_date_time(self) -> None:
        schema = {"type": "string", "format": "date-time"}
        validate_value("2026-07-13T07:00:00Z", schema)
        with self.assertRaisesRegex(ContractError, "timezone"):
            validate_value("2026-07-13T07:00:00", schema)

    def test_array_uniqueness_and_bounds_are_enforced(self) -> None:
        schema = {
            "type": "array",
            "items": {"type": "integer", "minimum": 1},
            "minItems": 1,
            "maxItems": 2,
            "uniqueItems": True,
        }
        validate_value([1, 2], schema)
        with self.assertRaisesRegex(ContractError, "duplicate"):
            validate_value([1, 1], schema)

    def test_non_finite_number_is_rejected(self) -> None:
        with self.assertRaisesRegex(ContractError, "finite"):
            validate_value(math.inf, {"type": "number"})


if __name__ == "__main__":
    unittest.main()
