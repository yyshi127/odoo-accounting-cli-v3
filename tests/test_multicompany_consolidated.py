"""Contract and accounting-oracle tests for the multi-company gross read."""

from __future__ import annotations

import json
from datetime import date
from decimal import Decimal
from pathlib import Path

import pytest

from odoo_accounting_cli_v3.contracts import validate_value
from odoo_accounting_cli_v3.domain.multicompany_consolidated import (
    CompanyAccountLedgerAggregate,
    CurrencyInfo,
    MulticompanyConsolidatedError,
    TechnicalRateSource,
    TranslationRate,
    read_multicompany_consolidated,
)


REGISTRY_PATH = Path(__file__).resolve().parents[1] / "registry" / "capabilities.json"


class FakeBackend:
    def __init__(self) -> None:
        self.calls: list[tuple[object, ...]] = []
        self.currencies = {
            7: CurrencyInfo(6, "CNY", "CNY", Decimal("0.01")),
            8: CurrencyInfo(1, "USD", "$", Decimal("0.01")),
        }
        self.presentation = CurrencyInfo(1, "USD", "$", Decimal("0.01"))
        self.aggregates = {
            7: (
                CompanyAccountLedgerAggregate(
                    7, 101, "1000", "Cash", "asset_cash",
                    Decimal("1000"), 1, Decimal("0"), Decimal("80"), 1,
                ),
                CompanyAccountLedgerAggregate(
                    7, 102, "1100", "Receivable", "asset_receivable",
                    Decimal("0"), 0, Decimal("200"), Decimal("0"), 1,
                ),
                CompanyAccountLedgerAggregate(
                    7, 201, "3000", "Equity", "equity",
                    Decimal("-1000"), 1, Decimal("0"), Decimal("0"), 0,
                ),
                CompanyAccountLedgerAggregate(
                    7, 301, "4000", "Revenue", "income",
                    Decimal("0"), 0, Decimal("0"), Decimal("200"), 1,
                ),
                CompanyAccountLedgerAggregate(
                    7, 401, "5000", "Expense", "expense",
                    Decimal("0"), 0, Decimal("80"), Decimal("0"), 1,
                ),
            ),
            8: (
                CompanyAccountLedgerAggregate(
                    8, 501, "1000", "Cash", "asset_cash",
                    Decimal("500"), 1, Decimal("0"), Decimal("50"), 1,
                ),
                CompanyAccountLedgerAggregate(
                    8, 502, "1100", "Receivable", "asset_receivable",
                    Decimal("0"), 0, Decimal("120"), Decimal("0"), 1,
                ),
                CompanyAccountLedgerAggregate(
                    8, 601, "3000", "Equity", "equity",
                    Decimal("-500"), 1, Decimal("0"), Decimal("0"), 0,
                ),
                CompanyAccountLedgerAggregate(
                    8, 701, "4000", "Revenue", "income",
                    Decimal("0"), 0, Decimal("0"), Decimal("120"), 1,
                ),
                CompanyAccountLedgerAggregate(
                    8, 801, "5000", "Expense", "expense",
                    Decimal("0"), 0, Decimal("50"), Decimal("0"), 1,
                ),
            ),
        }
        self.rates = {
            7: TranslationRate(
                company_id=7,
                rate_company_id=7,
                source_currency_id=6,
                presentation_currency_id=1,
                rate_date=date(2026, 6, 30),
                source_technical_source=TechnicalRateSource.no_rate_identity(
                    currency_id=6
                ),
                presentation_technical_source=TechnicalRateSource(
                    currency_id=1,
                    effective_date=date(2026, 6, 1),
                    source_scope="company_specific",
                    source_company_id=7,
                    source_record_id=701,
                    technical_rate=Decimal("0.14"),
                ),
                source_to_presentation_rate=Decimal("0.14"),
            ),
            8: TranslationRate(
                company_id=8,
                rate_company_id=8,
                source_currency_id=1,
                presentation_currency_id=1,
                rate_date=date(2026, 6, 30),
                source_technical_source=TechnicalRateSource.no_rate_identity(
                    currency_id=1
                ),
                presentation_technical_source=TechnicalRateSource.no_rate_identity(
                    currency_id=1
                ),
                source_to_presentation_rate=Decimal("1"),
            ),
        }

    def assert_read_access(
        self, *, company_ids: tuple[int, ...], presentation_currency_id: int
    ) -> None:
        self.calls.append(("access", company_ids, presentation_currency_id))

    def presentation_currency(
        self, *, company_ids: tuple[int, ...], currency_id: int
    ) -> CurrencyInfo:
        self.calls.append(("presentation", company_ids, currency_id))
        if currency_id != self.presentation.id:
            raise MulticompanyConsolidatedError(
                "presentation currency does not exist or is not visible"
            )
        return self.presentation

    def company_currency(self, *, company_id: int) -> CurrencyInfo:
        self.calls.append(("company_currency", company_id))
        return self.currencies[company_id]

    def ledger_account_aggregates(
        self,
        *,
        company_id: int,
        date_from: date,
        date_to: date,
        posted_only: bool,
        exclude_off_balance: bool,
    ) -> tuple[CompanyAccountLedgerAggregate, ...]:
        self.calls.append(
            (
                "ledger",
                company_id,
                date_from,
                date_to,
                posted_only,
                exclude_off_balance,
            )
        )
        return self.aggregates[company_id]

    def translation_rate(
        self,
        *,
        company_id: int,
        rate_date: date,
        source_currency: CurrencyInfo,
        presentation_currency: CurrencyInfo,
    ) -> TranslationRate:
        self.calls.append(
            (
                "rate",
                company_id,
                rate_date,
                source_currency.id,
                presentation_currency.id,
            )
        )
        return self.rates[company_id]


def parameters(**changes: object) -> dict[str, object]:
    result: dict[str, object] = {
        "company_ids": [8, 7],
        "date_from": "2026-01-01",
        "date_to": "2026-06-30",
        "presentation_currency_id": 1,
        "limit": 100,
        "offset": 0,
    }
    result.update(changes)
    return result


def receipt(record_count: int) -> dict[str, object]:
    return {
        "id": "receipt-test-multicompany-1",
        "odoo_instance_id": "odoo19@tokyo2",
        "database_name": "odoo_test",
        "database_uuid": "11111111-1111-4111-8111-111111111111",
        "company_id": 7,
        "user_id": 42,
        "capability_id": "acct.multicompany.consolidated_read.v1",
        "environment": "test",
        "capability_channel": "staged",
        "request_digest": "a" * 64,
        "result_digest": "b" * 64,
        "registry_digest": "c" * 64,
        "release_digest": "d" * 64,
        "record_count": record_count,
        "observed_at": "2026-07-13T07:00:00Z",
        "signature_version": 2,
        "signature_purpose": "read_receipt_v2",
        "signature_key_id": "test-receipt-2026-07",
        "signature": "e" * 64,
    }


def test_golden_is_posted_gross_translation_not_fake_consolidation() -> None:
    backend = FakeBackend()

    result = read_multicompany_consolidated(backend, parameters())

    assert [item["company_id"] for item in result["companies"]] == [7, 8]
    assert result["filters"]["company_ids"] == [7, 8]
    assert result["companies"][0]["source_balances"] == {
        "opening_balance": "0.00",
        "period_debit": "280.00",
        "period_credit": "280.00",
        "period_balance": "0.00",
        "closing_balance": "0.00",
    }
    assert result["companies"][0]["translated_balances"] == {
        "opening_balance": "0.00",
        "period_debit": "39.20",
        "period_credit": "39.20",
        "period_balance": "0.00",
        "closing_balance": "0.00",
    }
    assert result["gross_summary"] == {
        "company_count": 2,
        "account_count": 10,
        "account_type_count": 5,
        "posted_move_line_count": 12,
        "opening_balance": "0.00",
        "period_debit": "209.20",
        "period_credit": "209.20",
        "period_balance": "0.00",
        "closing_balance": "0.00",
        "balanced_company_count": 2,
        "unbalanced_company_ids": [],
        "translation_rounding_residuals": {
            "opening_balance": "0.00",
            "period_debit": "0.00",
            "period_credit": "0.00",
            "period_balance": "0.00",
            "closing_balance": "0.00",
        },
    }
    assert all(
        company["ledger_control"]["is_balanced"]
        for company in result["companies"]
    )
    assert result["account_lines"][0]["account"] == {
        "id": 101,
        "code": "1000",
        "name": "Cash",
        "account_type": "asset_cash",
    }
    assert result["account_lines"][0]["translated_balances"][
        "closing_balance"
    ] == "128.80"
    assert result["mapping_policy"] == {
        "status": "odoo_standard_account_type_only",
        "cross_company_account_mapping_computed": False,
    }
    assert result["elimination_policy"] == {
        "status": "not_computed",
        "reason": "no_explicit_elimination_dataset_or_mapping",
        "adjustments": [],
    }
    assert result["consolidation_status"]["complete_consolidation"] is False
    assert result["consolidation_status"]["status"] == "gross_translation_only"
    assert result["translation_policy"]["rate_date"] == "2026-06-30"
    assert result["translation_policy"]["historical_or_average_rates_applied"] is False
    assert result["translation_policy"]["translation_reserve_computed"] is False
    assert result["page"] == {
        "limit": 100,
        "offset": 0,
        "count": 10,
        "total_count": 10,
    }
    assert (
        "ledger",
        7,
        date(2026, 1, 1),
        date(2026, 6, 30),
        True,
        True,
    ) in backend.calls


def test_rate_sources_and_formula_are_disclosed_and_rechecked() -> None:
    backend = FakeBackend()

    result = read_multicompany_consolidated(backend, parameters())

    rate = result["companies"][0]["translation_rate"]
    assert rate["direction"] == "company_currency_to_presentation_currency"
    assert rate["formula"] == (
        "presentation_technical_rate / source_technical_rate"
    )
    assert rate["source_to_presentation_rate"] == "0.14"
    assert rate["presentation_technical_source"]["source_record_id"] == 701
    assert rate["source_technical_source"]["source_scope"] == "no_rate_identity"

    backend.rates[7] = TranslationRate(
        **{
            **backend.rates[7].__dict__,
            "source_to_presentation_rate": Decimal("0.15"),
        }
    )
    with pytest.raises(
        MulticompanyConsolidatedError, match="technical rate ratio"
    ):
        read_multicompany_consolidated(backend, parameters())


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"company_ids": []}, "company_ids"),
        ({"company_ids": [7, 7]}, "unique"),
        ({"company_ids": [True]}, "positive integers"),
        ({"date_from": "2026-02-30"}, "date_from"),
        (
            {"date_from": "2026-07-01", "date_to": "2026-06-30"},
            "must not be after",
        ),
        ({"presentation_currency_id": True}, "presentation_currency_id"),
        ({"limit": 1001}, "limit"),
        ({"offset": -1}, "offset"),
    ],
)
def test_invalid_scope_and_dates_fail_closed(
    changes: dict[str, object], message: str
) -> None:
    with pytest.raises(MulticompanyConsolidatedError, match=message):
        read_multicompany_consolidated(FakeBackend(), parameters(**changes))


def test_company_or_rate_binding_drift_fails_closed() -> None:
    backend = FakeBackend()
    first = backend.aggregates[7][0]
    backend.aggregates[7] = (
        CompanyAccountLedgerAggregate(
            **{**first.__dict__, "company_id": 8}
        ),
        *backend.aggregates[7][1:],
    )
    with pytest.raises(MulticompanyConsolidatedError, match="company binding"):
        read_multicompany_consolidated(backend, parameters())

    backend = FakeBackend()
    backend.rates[7] = TranslationRate(
        **{**backend.rates[7].__dict__, "presentation_currency_id": 2}
    )
    with pytest.raises(
        MulticompanyConsolidatedError, match="presentation currency binding"
    ):
        read_multicompany_consolidated(backend, parameters())


def test_company_specific_rate_must_match_disclosed_rate_company() -> None:
    backend = FakeBackend()
    backend.rates[7] = TranslationRate(
        **{**backend.rates[7].__dict__, "rate_company_id": 99}
    )

    with pytest.raises(
        MulticompanyConsolidatedError,
        match="outside the disclosed rate company",
    ):
        read_multicompany_consolidated(backend, parameters())


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("period_debit", Decimal("-0.01"), "debit must not be negative"),
        ("period_credit", Decimal("-0.01"), "credit must not be negative"),
    ],
)
def test_negative_debit_or_credit_is_rejected(
    field: str,
    value: Decimal,
    message: str,
) -> None:
    backend = FakeBackend()
    first = backend.aggregates[7][0]
    backend.aggregates[7] = (
        CompanyAccountLedgerAggregate(
            **{**first.__dict__, field: value}
        ),
        *backend.aggregates[7][1:],
    )

    with pytest.raises(MulticompanyConsolidatedError, match=message):
        read_multicompany_consolidated(backend, parameters())


def test_duplicate_accounts_and_per_company_safety_limit_are_rejected() -> None:
    backend = FakeBackend()
    backend.aggregates[7] = (
        backend.aggregates[7][0],
        backend.aggregates[7][0],
    )
    with pytest.raises(MulticompanyConsolidatedError, match="must be unique"):
        read_multicompany_consolidated(backend, parameters())

    backend = FakeBackend()
    backend.aggregates[7] = (
        backend.aggregates[7][0],
    ) * 10_001
    with pytest.raises(
        MulticompanyConsolidatedError,
        match="too many active accounts",
    ):
        read_multicompany_consolidated(backend, parameters())


def test_empty_ledger_and_offset_past_end_return_empty_pages_with_full_controls() -> None:
    backend = FakeBackend()
    backend.aggregates = {7: (), 8: ()}

    empty = read_multicompany_consolidated(backend, parameters())
    assert empty["account_lines"] == []
    assert empty["account_type_summaries"] == []
    assert empty["gross_summary"]["account_count"] == 0
    assert empty["gross_summary"]["balanced_company_count"] == 2
    assert empty["page"] == {
        "limit": 100,
        "offset": 0,
        "count": 0,
        "total_count": 0,
    }

    result = read_multicompany_consolidated(
        FakeBackend(),
        parameters(limit=3, offset=999),
    )
    assert result["account_lines"] == []
    assert result["gross_summary"]["account_count"] == 10
    assert result["page"] == {
        "limit": 3,
        "offset": 999,
        "count": 0,
        "total_count": 10,
    }


def test_per_account_rounding_residual_and_balance_equations_are_explicit() -> None:
    backend = FakeBackend()
    backend.aggregates[7] = (
        CompanyAccountLedgerAggregate(
            7,
            101,
            "1000",
            "Cash",
            "asset_cash",
            Decimal("0"),
            0,
            Decimal("0.01"),
            Decimal("0.02"),
            2,
        ),
    )
    backend.rates[7] = TranslationRate(
        **{
            **backend.rates[7].__dict__,
            "presentation_technical_source": TechnicalRateSource(
                currency_id=1,
                effective_date=date(2026, 6, 1),
                source_scope="company_specific",
                source_company_id=7,
                source_record_id=702,
                technical_rate=Decimal("0.5"),
            ),
            "source_to_presentation_rate": Decimal("0.5"),
        }
    )

    result = read_multicompany_consolidated(
        backend,
        parameters(company_ids=[7]),
    )
    line = result["account_lines"][0]
    assert line["translated_balances"]["period_debit"] == "0.01"
    assert line["translated_balances"]["period_credit"] == "0.01"
    assert line["translated_balances"]["period_balance"] == "0.00"
    assert line["translation_rounding_residuals"]["period_balance"] == "-0.01"
    assert set(line["balance_equation_control"].values()) == {True}


def test_account_paging_is_stable_but_summaries_cover_the_full_set() -> None:
    result = read_multicompany_consolidated(
        FakeBackend(),
        parameters(limit=3, offset=2),
    )

    assert result["page"] == {
        "limit": 3,
        "offset": 2,
        "count": 3,
        "total_count": 10,
    }
    assert [
        (item["company_id"], item["account"]["code"])
        for item in result["account_lines"]
    ] == [(7, "3000"), (7, "4000"), (7, "5000")]
    assert result["gross_summary"]["account_count"] == 10
    assert result["gross_summary"]["period_debit"] == "209.20"


def test_result_plus_common_signed_receipt_matches_registry_schema() -> None:
    result = read_multicompany_consolidated(FakeBackend(), parameters())
    result["receipt"] = receipt(record_count=10)
    registry = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    capability = next(
        item
        for item in registry["capabilities"]
        if item["id"] == "acct.multicompany.consolidated_read.v1"
    )

    validate_value(result, capability["output_schema"])
