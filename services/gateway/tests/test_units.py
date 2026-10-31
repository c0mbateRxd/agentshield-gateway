from datetime import date

import pytest

from app.core import rules as rl
from app.core.formatting import format_inr
from app.core.lease import LeaseInvalid, LeaseKeys, generate_keypair
from app.core.names import bank_name_score, normalise
from app.core.reasons import ReasonCode as R
from app.core.reasons import http_status

CFG = {"price_tolerance": 0.05, "bank_match_allow": 90, "bank_match_hold": 70, "cooling_off_days": 3,
       "bank_change_lookback_hours": 24, "high_value_approval_inr": 200000}
SCOPE = {"suppliers": ["100045"], "purchase_orders": ["4500017"], "max_payment_inr": 5000000}
TODAY = date(2026, 11, 3)


@pytest.mark.parametrize("n,s", [(980000, "₹9,80,000"), (4850000, "₹48,50,000"), (270000, "₹2,70,000"),
                                 (800000, "₹8,00,000"), (999, "₹999"), (1000, "₹1,000"), (12345678, "₹1,23,45,678"),
                                 (0, "₹0"), (-5000, "-₹5,000"), (10290000.5, "₹1,02,90,000.5")])
def test_format_inr(n, s):
    assert format_inr(n) == s


def test_names():
    assert normalise("Acme Components Pvt. Ltd & Co") == "ACME COMPONENTS CO"
    assert bank_name_score("ACME COMPONENTS PVT LTD", "Acme Components Private Limited", "ACME") >= 90
    assert bank_name_score("RAJESH TRADERS", "Acme Components Private Limited", "ACME") < 70


def test_lease_sign_verify_tamper():
    priv, pub = generate_keypair()
    keys = LeaseKeys("k1", priv, None)
    tok = keys.sign({"lease_id": "l1", "scope": {"max_calls": 1}})
    assert keys.verify(tok)["lease_id"] == "l1"
    body, sig = tok.split(".")
    forged = ("A" if body[0] != "A" else "B") + body[1:]
    with pytest.raises(LeaseInvalid):
        keys.verify(f"{forged}.{sig}")
    with pytest.raises(LeaseInvalid):
        keys.verify("garbage")
    with pytest.raises(LeaseInvalid):
        LeaseKeys("other-kid", None, pub).verify(tok)
    other_priv, _ = generate_keypair()
    with pytest.raises(LeaseInvalid):
        LeaseKeys("k1", other_priv, None).verify(tok)


def test_http_status_mapping():
    assert http_status(R.ALLOW_OK) == 200 and http_status(R.HOLD_BANK_COOLING_OFF) == 202
    assert http_status(R.DENY_PRICE_VARIANCE) == 403 and http_status(R.DENY_AGENT_UNAUTHENTICATED) == 401
    assert all(http_status(c) == 409 for c in (R.DENY_NONCE_REUSED, R.DENY_DUPLICATE_PAYMENT,
                                                R.DENY_CONCURRENT_MODIFICATION))


# ---- table-driven rule tests ----------------------------------------------------------------------------

PO = {"items": [{"PurchaseOrderItem": "10", "NetPriceAmount": 10000}],
      "YY1_AirFreightQuoteInr": 950000, "YY1_SeaFreightPlannedInr": 150000, "YY1_DelayPenaltyPerDayInr": 100000}
GR = {"receipts": [{"PurchaseOrderItem": "10", "QuantityInEntryUnit": 100}]}
INV = {"SupplierInvoice": "1", "Supplier": "100045", "InvoiceGrossAmount": 980000, "Status": "POSTED"}
BANK_OLD = {"ValidityStartDate": "2026-01-01"}
ORC_OK = {"penny_drop": {"holder_name": "ACME COMPONENTS PVT LTD"},
          "gstin": {"legal_name": "Acme Components Private Limited", "trade_name": "ACME"}}


def inp(args, erp=None, oracle=None, history=None, scope=SCOPE):
    return rl.RuleInput(args=args, erp=erp or {}, cfg=CFG, scope=scope, today=TODAY, oracle=oracle or {},
                        history=history or {})


def item(price, qty=100):
    return {"purchase_order_item": "10", "quantity": qty, "unit_price_inr": price}


RULE_CASES = [
    # (id, rule, input, expected reason or None, expected risk)
    ("inv01-ok", rl.r_inv_01, inp({"items": [item(10500)]}, {"purchase_order": PO}), None, 0),
    ("inv01-variance", rl.r_inv_01, inp({"items": [item(12700)]}, {"purchase_order": PO}), R.DENY_PRICE_VARIANCE, 270000),
    ("inv01-unknown-item", rl.r_inv_01, inp({"items": [{**item(1), "purchase_order_item": "99"}]}, {"purchase_order": PO}),
     R.DENY_OBJECT_NOT_IN_SCOPE, 0),
    ("inv02-ok", rl.r_inv_02, inp({"items": [item(1, 100)]}, {"goods_receipts": GR, "invoices": {"invoices": []}}), None, 0),
    ("inv02-over", rl.r_inv_02, inp({"items": [item(1, 101)]}, {"goods_receipts": GR, "invoices": {"invoices": []}}),
     R.DENY_QTY_EXCEEDS_GR, 0),
    ("inv02-prior", rl.r_inv_02, inp({"items": [item(1, 50)]}, {"goods_receipts": GR, "invoices": {"invoices": [
        {"Status": "POSTED", "items": [{"PurchaseOrderItem": "10", "Quantity": 60}]}]}}), R.DENY_QTY_EXCEEDS_GR, 0),
    ("inv03-ok", rl.r_inv_03, inp({"items": [item(10, 2)], "gross_amount_inr": 20}), None, 0),
    ("inv03-mismatch", rl.r_inv_03, inp({"items": [item(10, 2)], "gross_amount_inr": 25}), R.DENY_AMOUNT_MISMATCH, 5),
    ("pay01-ok", rl.r_pay_01, inp({}, {"invoice": INV}), None, 0),
    ("pay01-missing", rl.r_pay_01, inp({}, {"invoice": None}), R.DENY_INVOICE_NOT_PAYABLE, 0),
    ("pay01-paid", rl.r_pay_01, inp({}, {"invoice": {**INV, "Status": "PAID"}}), R.DENY_DUPLICATE_PAYMENT, 980000),
    ("pay01-draft", rl.r_pay_01, inp({}, {"invoice": {**INV, "Status": "DRAFT"}}), R.DENY_INVOICE_NOT_PAYABLE, 0),
    ("pay01-scope", rl.r_pay_01, inp({}, {"invoice": {**INV, "Supplier": "7"}}), R.DENY_OBJECT_NOT_IN_SCOPE, 0),
    ("pay02-ok", rl.r_pay_02, inp({"amount_inr": 980000}, {"invoice": INV}), None, 0),
    ("pay02-mismatch", rl.r_pay_02, inp({"amount_inr": 100}, {"invoice": INV}), R.DENY_AMOUNT_MISMATCH, 979900),
    ("pay03-ok", rl.r_pay_03, inp({}, {"invoice": INV}), None, 0),
    ("pay03-over", rl.r_pay_03, inp({}, {"invoice": {**INV, "InvoiceGrossAmount": 6000000}}),
     R.DENY_AMOUNT_EXCEEDS_LEASE, 6000000),
    ("pay04-ok", rl.r_pay_04, inp({}, {"invoice": INV}), None, 0),
    ("pay04-review", rl.r_pay_04, inp({}, {"invoice": INV}, history={"recent_bank_decisions": 1}),
     R.HOLD_BANK_CHANGE_UNDER_REVIEW, 980000),
    ("pay05-ok", rl.r_pay_05, inp({}, {"invoice": INV, "bank": BANK_OLD}), None, 0),
    ("pay05-cooling", rl.r_pay_05, inp({}, {"invoice": INV, "bank": {"ValidityStartDate": "2026-11-02"}}),
     R.HOLD_BANK_COOLING_OFF, 980000),
    ("pay05-boundary", rl.r_pay_05, inp({}, {"invoice": INV, "bank": {"ValidityStartDate": "2026-10-31"}}), None, 0),
    ("bank02-down", rl.r_bank_02, inp({}, oracle={"error": "timeout"}), R.HOLD_ORACLE_UNAVAILABLE, 0),
    ("bank02-up", rl.r_bank_02, inp({}, oracle=ORC_OK), None, 0),
    ("bank01-match", rl.r_bank_01, inp({}, {"invoices": {"invoices": []}}, ORC_OK), None, 0),
    ("bank01-partial", rl.r_bank_01, inp({}, {"invoices": {"invoices": []}}, {
        "penny_drop": {"holder_name": "ACMEE COMPONENT SALES"}, "gstin": {"legal_name": "Acme Components Private Limited",
                                                                     "trade_name": "ACME Components"}}),
     R.HOLD_BANK_NAME_PARTIAL, 0),
    ("bank01-mismatch", rl.r_bank_01, inp({}, {"invoices": {"invoices": [
        {"Status": "POSTED", "InvoiceGrossAmount": 980000}, {"Status": "POSTED", "InvoiceGrossAmount": 3870000},
        {"Status": "PAID", "InvoiceGrossAmount": 5}]}}, {
        "penny_drop": {"holder_name": "RAJESH TRADERS"}, "gstin": {"legal_name": "Acme Components Private Limited",
                                                                    "trade_name": "ACME"}}),
     R.DENY_BANK_NAME_MISMATCH, 4850000),
    ("frt01-ok", rl.r_frt_01, inp({"mode": "AIR", "claimed_delay_days": 10}, {"purchase_order": PO}), None, 0),
    ("frt01-uneconomic", rl.r_frt_01, inp({"mode": "AIR", "claimed_delay_days": 2}, {"purchase_order": PO}),
     R.DENY_FREIGHT_UNECONOMIC, 800000),
    ("frt01-sea-skipped", rl.r_frt_01, inp({"mode": "SEA", "claimed_delay_days": 0}, {"purchase_order": PO}), None, 0),
    ("frt02-disrupted", rl.r_frt_02, inp({"mode": "AIR"}, {"purchase_order": PO},
                                         {"ais": {"port": "P", "berthed_today": 1, "threshold": 5}}), None, 0),
    ("frt02-contradicted", rl.r_frt_02, inp({"mode": "AIR"}, {"purchase_order": PO},
                                            {"ais": {"port": "P", "berthed_today": 9, "threshold": 5}}),
     R.DENY_SIGNAL_CONTRADICTED, 800000),
    ("frt02-oracle-down", rl.r_frt_02, inp({"mode": "AIR"}, {"purchase_order": PO}, {"error": "t"}),
     R.HOLD_ORACLE_UNAVAILABLE, 0),
    ("frt03-high", rl.r_frt_03, inp({"mode": "AIR"}, {"purchase_order": PO}), R.HOLD_AMOUNT_NEEDS_APPROVAL, 0),
    ("frt03-low", rl.r_frt_03, inp({"mode": "AIR"}, {"purchase_order": {**PO, "YY1_AirFreightQuoteInr": 150000}}), None, 0),
]


@pytest.mark.parametrize("rule,i,reason,risk", [c[1:] for c in RULE_CASES], ids=[c[0] for c in RULE_CASES])
def test_rule_table(rule, i, reason, risk):
    out = rule(i)
    assert out.reason == reason
    assert out.ok == (reason is None)
    assert out.inr_at_risk == risk


def test_formula_strings_are_exact():
    out = rl.r_inv_01(inp({"items": [item(12700)]}, {"purchase_order": PO}))
    assert out.formula == "invoice ₹12,700 > PO ₹10,000 × 1.05 = ₹10,500.00 (+27.0%)".replace(".00", "")
    out = rl.r_frt_01(inp({"mode": "AIR", "claimed_delay_days": 2}, {"purchase_order": PO}))
    assert out.formula == "air ₹9,50,000 − sea ₹1,50,000 = ₹8,00,000 ≥ 2 d × ₹1,00,000 = ₹2,00,000 penalty avoided"
