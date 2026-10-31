"""Deterministic rules (spec 10.3). Every rule is a pure function of RuleInput: no I/O, no clock, no DB.
ERP data in, Outcome out. The pipeline gathers `erp`, `oracle` and `history` beforehand."""
from dataclasses import dataclass, field
from datetime import date
from decimal import Decimal

from app.core.formatting import format_inr
from app.core.names import bank_name_score
from app.core.reasons import ReasonCode as R


@dataclass
class RuleInput:
    args: dict
    erp: dict                       # authoritative ERP data fetched by the pipeline
    cfg: dict                       # policy/rules.yaml
    scope: dict                     # lease scope (DB copy)
    today: date
    oracle: dict = field(default_factory=dict)   # {"penny_drop":..., "gstin":..., "ais":..., "error": str|None}
    history: dict = field(default_factory=dict)  # {"recent_bank_decisions": int}


@dataclass
class Outcome:
    rule_id: str
    ok: bool = True
    skipped: bool = False
    reason: R | None = None
    message: str = ""
    inr_at_risk: int = 0
    formula: str | None = None


def _ok(rule_id: str, msg: str = "") -> Outcome:
    return Outcome(rule_id, message=msg)


def _fail(rule_id: str, reason: R, msg: str, risk=0, formula=None) -> Outcome:
    return Outcome(rule_id, ok=False, reason=reason, message=msg, inr_at_risk=int(risk), formula=formula)


def _skip(rule_id: str, msg: str) -> Outcome:
    return Outcome(rule_id, skipped=True, message=msg)


def _d(x) -> Decimal:
    return Decimal(str(x))


def _po_items(erp) -> dict:
    return {i["PurchaseOrderItem"]: i for i in erp["purchase_order"].get("items", [])}


# ---- invoices -------------------------------------------------------------------------------------------

def r_inv_01(i: RuleInput) -> Outcome:
    tol = _d(i.cfg["price_tolerance"])
    po_items, bad, parts, risk = _po_items(i.erp), [], [], Decimal(0)
    for it in i.args["items"]:
        po = po_items.get(it["purchase_order_item"])
        if po is None:
            return _fail("R-INV-01", R.DENY_OBJECT_NOT_IN_SCOPE,
                         f"PO item {it['purchase_order_item']} is not on the purchase order")
        price, claimed = _d(po["NetPriceAmount"]), _d(it["unit_price_inr"])
        limit = price * (1 + tol)
        if claimed > limit:
            bad.append(it)
            risk += it["quantity"] * (claimed - price)
            pct = (claimed / price - 1) * 100
            parts.append(f"invoice {format_inr(claimed)} > PO {format_inr(price)} × {1 + tol} = "
                         f"{format_inr(limit)} (+{pct:.1f}%)")
    if bad:
        return _fail("R-INV-01", R.DENY_PRICE_VARIANCE, "Invoice unit price exceeds PO price tolerance",
                     risk, "; ".join(parts))
    return _ok("R-INV-01", "unit prices within PO tolerance")


def r_inv_02(i: RuleInput) -> Outcome:
    received: dict[str, int] = {}
    for g in i.erp["goods_receipts"].get("receipts", []):
        received[g["PurchaseOrderItem"]] = received.get(g["PurchaseOrderItem"], 0) + int(g["QuantityInEntryUnit"])
    before: dict[str, int] = {}
    for inv in i.erp["invoices"].get("invoices", []):
        if inv.get("Status") == "CANCELLED":
            continue
        for it in inv.get("items", []):
            before[it["PurchaseOrderItem"]] = before.get(it["PurchaseOrderItem"], 0) + int(it["Quantity"])
    for it in i.args["items"]:
        k = it["purchase_order_item"]
        total = before.get(k, 0) + it["quantity"]
        if total > received.get(k, 0):
            return _fail("R-INV-02", R.DENY_QTY_EXCEEDS_GR,
                         f"Item {k}: invoiced qty {total} exceeds goods received {received.get(k, 0)}",
                         formula=f"invoiced {before.get(k, 0)} + {it['quantity']} = {total} > GR {received.get(k, 0)}")
    return _ok("R-INV-02", "invoiced qty within goods receipts")


def r_inv_03(i: RuleInput) -> Outcome:
    total = sum(it["quantity"] * it["unit_price_inr"] for it in i.args["items"])
    if total != i.args["gross_amount_inr"]:
        return _fail("R-INV-03", R.DENY_AMOUNT_MISMATCH, "Gross amount does not equal sum of line items",
                     abs(total - i.args["gross_amount_inr"]),
                     f"gross {format_inr(i.args['gross_amount_inr'])} ≠ Σ qty × price = {format_inr(total)}")
    return _ok("R-INV-03", "gross equals line total")


# ---- payments -------------------------------------------------------------------------------------------

def r_pay_01(i: RuleInput) -> Outcome:
    inv = i.erp.get("invoice")
    if inv is None:
        return _fail("R-PAY-01", R.DENY_INVOICE_NOT_PAYABLE, "Invoice does not exist in ERP")
    if inv["Status"] == "PAID":
        return _fail("R-PAY-01", R.DENY_DUPLICATE_PAYMENT, "Invoice is already paid", inv["InvoiceGrossAmount"],
                     f"invoice {inv['SupplierInvoice']} already PAID; paying again risks "
                     f"{format_inr(inv['InvoiceGrossAmount'])}")
    if inv["Status"] != "POSTED":
        return _fail("R-PAY-01", R.DENY_INVOICE_NOT_PAYABLE, f"Invoice status is {inv['Status']}, not POSTED")
    if inv["Supplier"] not in i.scope.get("suppliers", []):
        return _fail("R-PAY-01", R.DENY_OBJECT_NOT_IN_SCOPE, "Invoice supplier is outside the lease scope")
    return _ok("R-PAY-01", "invoice POSTED, unpaid, supplier in lease")


def r_pay_02(i: RuleInput) -> Outcome:
    inv = i.erp.get("invoice")
    if inv is None:
        return _skip("R-PAY-02", "no invoice")
    if i.args["amount_inr"] != inv["InvoiceGrossAmount"]:
        gross = inv["InvoiceGrossAmount"]
        return _fail("R-PAY-02", R.DENY_AMOUNT_MISMATCH, "Payment amount differs from invoice gross",
                     abs(i.args["amount_inr"] - gross),
                     f"amount {format_inr(i.args['amount_inr'])} ≠ invoice gross {format_inr(gross)}")
    return _ok("R-PAY-02", "amount equals invoice gross")


def r_pay_03(i: RuleInput) -> Outcome:
    inv = i.erp.get("invoice")
    if inv is None:
        return _skip("R-PAY-03", "no invoice")
    cap, gross = i.scope["max_payment_inr"], inv["InvoiceGrossAmount"]
    if gross > cap:
        return _fail("R-PAY-03", R.DENY_AMOUNT_EXCEEDS_LEASE, "Payment exceeds lease ceiling", gross,
                     f"invoice {format_inr(gross)} > lease max {format_inr(cap)}")
    return _ok("R-PAY-03", "within lease ceiling")


def r_pay_04(i: RuleInput) -> Outcome:
    inv = i.erp.get("invoice")
    if inv is not None and i.history.get("recent_bank_decisions", 0) > 0:
        return _fail("R-PAY-04", R.HOLD_BANK_CHANGE_UNDER_REVIEW,
                     "A bank change for this supplier was denied or held in the last "
                     f"{i.cfg['bank_change_lookback_hours']} h", inv["InvoiceGrossAmount"],
                     f"{format_inr(inv['InvoiceGrossAmount'])} payable to a supplier with an unresolved bank change")
    return _ok("R-PAY-04", "no recent denied/held bank change")


def r_pay_05(i: RuleInput) -> Outcome:
    inv, bank = i.erp.get("invoice"), i.erp.get("bank")
    if inv is None or bank is None:
        return _skip("R-PAY-05", "no invoice or bank")
    age = (i.today - date.fromisoformat(bank["ValidityStartDate"])).days
    need = i.cfg["cooling_off_days"]
    if age < need:
        return _fail("R-PAY-05", R.HOLD_BANK_COOLING_OFF, "Supplier bank details changed too recently",
                     inv["InvoiceGrossAmount"], f"bank details {age} d old < cooling-off {need} d")
    return _ok("R-PAY-05", f"bank details {age} d old")


# ---- bank change ----------------------------------------------------------------------------------------

def r_bank_02(i: RuleInput) -> Outcome:
    if i.oracle.get("error"):
        return _fail("R-BANK-02", R.HOLD_ORACLE_UNAVAILABLE, f"Oracle unavailable: {i.oracle['error']}")
    return _ok("R-BANK-02", "oracles reachable")


def r_bank_01(i: RuleInput) -> Outcome:
    if i.oracle.get("error"):
        return _skip("R-BANK-01", "oracle unavailable")
    holder = i.oracle["penny_drop"]["holder_name"]
    legal, trade = i.oracle["gstin"]["legal_name"], i.oracle["gstin"]["trade_name"]
    score = bank_name_score(holder, legal, trade)
    formula = f"penny-drop '{holder}' vs GSTIN legal '{legal}' / trade '{trade}': match {score:.0f}%"
    if score >= i.cfg["bank_match_allow"]:
        return _ok("R-BANK-01", formula)
    if score >= i.cfg["bank_match_hold"]:
        return _fail("R-BANK-01", R.HOLD_BANK_NAME_PARTIAL, "Bank holder name only partially matches GSTIN",
                     formula=f"{formula} (allow ≥ {i.cfg['bank_match_allow']}%)")
    open_total = sum(inv["InvoiceGrossAmount"] for inv in i.erp["invoices"].get("invoices", [])
                     if inv.get("Status") == "POSTED")
    return _fail("R-BANK-01", R.DENY_BANK_NAME_MISMATCH, "Bank holder name does not match GSTIN legal/trade name",
                 open_total, f"{formula} < {i.cfg['bank_match_hold']}%; open invoices at risk {format_inr(open_total)}")


# ---- freight --------------------------------------------------------------------------------------------

def _air(i: RuleInput) -> bool:
    return i.args["mode"] == "AIR"


def r_frt_01(i: RuleInput) -> Outcome:
    if not _air(i):
        return _skip("R-FRT-01", "not air freight")
    po = i.erp["purchase_order"]
    air, sea, per_day = po["YY1_AirFreightQuoteInr"], po["YY1_SeaFreightPlannedInr"], po["YY1_DelayPenaltyPerDayInr"]
    days = i.args["claimed_delay_days"]
    extra, avoided = air - sea, days * per_day
    formula = (f"air {format_inr(air)} − sea {format_inr(sea)} = {format_inr(extra)} "
               f"{'<' if extra < avoided else '≥'} {days} d × {format_inr(per_day)} = {format_inr(avoided)} penalty avoided")
    if extra < avoided:
        return _ok("R-FRT-01", formula)
    return _fail("R-FRT-01", R.DENY_FREIGHT_UNECONOMIC, "Air freight costs more than the delay penalty it avoids",
                 extra, formula)


def r_frt_02(i: RuleInput) -> Outcome:
    if not _air(i):
        return _skip("R-FRT-02", "not air freight")
    if i.oracle.get("error"):
        return _fail("R-FRT-02", R.HOLD_ORACLE_UNAVAILABLE, f"AIS oracle unavailable: {i.oracle['error']}")
    ais = i.oracle["ais"]
    formula = f"AIS {ais['port']}: berthed_today {ais['berthed_today']} vs disruption threshold {ais['threshold']}"
    if ais["berthed_today"] < ais["threshold"]:
        return _ok("R-FRT-02", formula)
    po = i.erp["purchase_order"]
    return _fail("R-FRT-02", R.DENY_SIGNAL_CONTRADICTED, "Authoritative AIS feed shows no port disruption",
                 po["YY1_AirFreightQuoteInr"] - po["YY1_SeaFreightPlannedInr"], formula)


def r_frt_03(i: RuleInput) -> Outcome:
    if not _air(i):
        return _skip("R-FRT-03", "not air freight")
    cost, cap = i.erp["purchase_order"]["YY1_AirFreightQuoteInr"], i.cfg["high_value_approval_inr"]
    if cost > cap:
        return _fail("R-FRT-03", R.HOLD_AMOUNT_NEEDS_APPROVAL, "High-value air freight needs human approval",
                     formula=f"air {format_inr(cost)} > approval threshold {format_inr(cap)}")
    return _ok("R-FRT-03", f"air {format_inr(cost)} ≤ {format_inr(cap)}")


# Table order is evaluation order; the first failing rule sets reason_code (spec R-ORD-00).
RULES = {
    "post_supplier_invoice": [r_inv_01, r_inv_02, r_inv_03],
    "execute_payment": [r_pay_01, r_pay_02, r_pay_03, r_pay_04, r_pay_05],
    "update_supplier_bank": [r_bank_02, r_bank_01],
    "book_freight": [r_frt_01, r_frt_02, r_frt_03],
}


def evaluate(tool: str, inp: RuleInput) -> list[Outcome]:
    return [rule(inp) for rule in RULES.get(tool, [])]
