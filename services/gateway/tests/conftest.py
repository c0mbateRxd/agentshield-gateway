import copy
import threading
import uuid
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from app.core.auth import issue_token
from app.core.erp import ErpConflict, ErpNotFound
from app.core.lease import generate_keypair
from app.core.oracles import OracleError
from app.main import create_app
from app.settings import Settings

SECRET = "test-secret"
TODAY = datetime.now(UTC).date().isoformat()


class FakeErp:
    """Same interface as ErpClient. Holds the 'authoritative' state used by the rules."""

    profile = "PROTECTED"

    def __init__(self):
        self.lock = threading.Lock()
        self.before_write = None
        self.writes: list[tuple] = []
        self.idem: dict = {}
        self.versions: dict = {}
        self.down = False
        self.suppliers = {"100045": {"Supplier": "100045", "SupplierName": "ACME Components Pvt Ltd",
                                     "GSTIN": "29ABCDE1234F1Z5", "EmailDomain": "acme.in"}}
        self.banks = {"100045": {"Supplier": "100045", "BankIdentification": "HDFC0001",
                                 "BankAccountMasked": "XXXX1234", "IFSC": "HDFC0000123",
                                 "BankAccountHolderName": "ACME COMPONENTS PRIVATE LIMITED",
                                 "ValidityStartDate": "2026-01-01"}}
        self.pos = {
            "4500017": {"PurchaseOrder": "4500017", "Supplier": "100045", "items": [
                {"PurchaseOrderItem": "10", "Material": "M1", "OrderQuantity": 1, "NetPriceAmount": 980000, "Currency": "INR"}]},
            "4500021": {"PurchaseOrder": "4500021", "Supplier": "100045", "items": [
                {"PurchaseOrderItem": "10", "Material": "M2", "OrderQuantity": 100, "NetPriceAmount": 10000, "Currency": "INR"}]},
            "4500030": {"PurchaseOrder": "4500030", "Supplier": "100045", "YY1_PortCode": "INMAA",
                        "YY1_AirFreightQuoteInr": 950000, "YY1_SeaFreightPlannedInr": 150000,
                        "YY1_DelayPenaltyPerDayInr": 100000, "items": []},
            "4500099": {"PurchaseOrder": "4500099", "Supplier": "999999", "items": []},
        }
        self.grs = {"4500017": [("10", 1)], "4500021": [("10", 100)]}
        self.invoices = {
            ("2026", "5105600031"): {"SupplierInvoice": "5105600031", "FiscalYear": "2026", "Supplier": "100045",
                                     "PurchaseOrder": "4500017", "InvoiceGrossAmount": 980000, "Status": "POSTED",
                                     "items": [{"PurchaseOrderItem": "10", "Quantity": 1}]},
            ("2026", "5105600032"): {"SupplierInvoice": "5105600032", "FiscalYear": "2026", "Supplier": "100045",
                                     "PurchaseOrder": "4500030", "InvoiceGrossAmount": 3870000, "Status": "POSTED",
                                     "items": []},
            ("2026", "5105600040"): {"SupplierInvoice": "5105600040", "FiscalYear": "2026", "Supplier": "100045",
                                     "PurchaseOrder": "4500030", "InvoiceGrossAmount": 100000, "Status": "PAID",
                                     "items": []},
            ("2026", "5105600041"): {"SupplierInvoice": "5105600041", "FiscalYear": "2026", "Supplier": "100045",
                                     "PurchaseOrder": "4500030", "InvoiceGrossAmount": 100000, "Status": "DRAFT",
                                     "items": []},
        }
        self.inbox = {"messages": [
            {"message_id": "m1", "from_address": "ap@acme.in", "from_domain": "acme.in", "subject": "Invoice",
             "received_at": "2026-10-30T10:00:00Z", "body_preview": "see attached", "attachments": []},
            {"message_id": "m2", "from_address": "x@evil.example", "from_domain": "evil.example", "subject": "Bank",
             "received_at": "2026-10-30T11:00:00Z", "body_preview": "new bank", "attachments": []}]}

    def etag(self, kind, key):
        return f'"{kind}{key}-{self.versions.get((kind, key), 1)}"'

    def bump(self, kind, key):
        self.versions[(kind, key)] = self.versions.get((kind, key), 1) + 1

    def read(self, kind, **p):
        if self.down:
            from app.core.erp import ErpUnavailable
            raise ErpUnavailable("down")
        if kind == "inbox":
            return copy.deepcopy(self.inbox), None
        if kind == "supplier_by_domain":
            for s in self.suppliers.values():
                if s["EmailDomain"] == p["domain"]:
                    return dict(s), None
            raise ErpNotFound(p["domain"])
        if kind == "purchase_orders_for_supplier":
            return {"purchase_orders": [{"PurchaseOrder": k} for k, v in self.pos.items()
                                        if v["Supplier"] == p["supplier"]]}, None
        if kind == "purchase_order":
            if p["purchase_order"] not in self.pos:
                raise ErpNotFound("po")
            return copy.deepcopy(self.pos[p["purchase_order"]]), self.etag("po", p["purchase_order"])
        if kind == "goods_receipts":
            return {"receipts": [{"MaterialDocument": "5000", "PurchaseOrderItem": i, "QuantityInEntryUnit": q,
                                  "PostingDate": "2026-10-01"} for i, q in self.grs.get(p["purchase_order"], [])]}, None
        if kind == "supplier":
            if p["supplier"] not in self.suppliers:
                raise ErpNotFound("supplier")
            return dict(self.suppliers[p["supplier"]]), self.etag("sup", p["supplier"])
        if kind == "supplier_bank":
            if p["supplier"] not in self.banks:
                raise ErpNotFound("bank")
            return dict(self.banks[p["supplier"]]), self.etag("bank", p["supplier"])
        if kind == "invoices":
            sup = p.get("supplier")
            return {"invoices": [copy.deepcopy(i) for i in self.invoices.values()
                                 if not sup or i["Supplier"] == sup]}, None
        if kind == "invoice":
            inv = self.invoices.get((p["fiscal_year"], p["supplier_invoice"]))
            if not inv:
                raise ErpNotFound("invoice")
            return copy.deepcopy(inv), self.etag("inv", p["supplier_invoice"])
        if kind == "document":
            return {"document_id": p["document_id"], "filename": "inv.pdf", "text": "x" * 5000}, None
        raise AssertionError(kind)

    def write(self, tool, args, if_match, idempotency_key):
        if self.before_write:
            self.before_write(self)
        with self.lock:
            if idempotency_key in self.idem:
                return self.idem[idempotency_key]
            if tool == "execute_payment":
                inv = self.invoices[(args["fiscal_year"], args["supplier_invoice"])]
                if if_match is not None and if_match != self.etag("bank", inv["Supplier"]):
                    raise ErpConflict("etag")
                if inv["Status"] == "PAID":
                    raise ErpConflict("duplicate")
                inv["Status"] = "PAID"
                out = {"PaymentId": str(uuid.uuid4()), "SupplierInvoice": inv["SupplierInvoice"],
                       "AmountInr": args["amount_inr"], "Status": "PAID"}
            elif tool == "update_supplier_bank":
                if if_match is not None and if_match != self.etag("bank", args["supplier"]):
                    raise ErpConflict("etag")
                self.banks[args["supplier"]].update(BankAccountHolderName=args["bank_account_holder_name"],
                                                    ValidityStartDate=TODAY)
                self.bump("bank", args["supplier"])
                out = {"Supplier": args["supplier"], "Status": "UPDATED"}
            elif tool == "post_supplier_invoice":
                out = {"SupplierInvoice": "5105609999", "FiscalYear": "2026", "Status": "POSTED"}
            else:
                out = {"BookingId": "B1", "Mode": args["mode"], "CostInr": args["quoted_cost_inr"]}
            self.writes.append((tool, dict(args), idempotency_key))
            if idempotency_key:
                self.idem[idempotency_key] = out
            return out

    def state_digest(self):
        return {"digest": "x"}

    def reset(self):
        self.writes.clear()


class FakeOracles:
    def __init__(self):
        self.holder = "ACME COMPONENTS PVT LTD"
        self.legal = "Acme Components Private Limited"
        self.trade = "ACME"
        self.berthed = 1      # < threshold => disruption confirmed
        self.threshold = 5
        self.fail = False

    def _chk(self):
        if self.fail:
            raise OracleError("timeout")

    def penny_drop(self, account, ifsc):
        self._chk()
        return {"holder_name": self.holder}

    def gstin(self, gstin):
        self._chk()
        return {"legal_name": self.legal, "trade_name": self.trade}

    def ais(self, port):
        self._chk()
        return {"port": port, "berthed_today": self.berthed, "threshold": self.threshold}

    def health(self):
        return {"status": "ok"}


class Harness:
    def __init__(self, client, erp, oracles, app):
        self.c, self.erp, self.oracles, self.app = client, erp, oracles, app
        self.ctx = app.state.ctx
        self.agent_token = issue_token(SECRET, "agent:ap-agent-01", ["agent"], 24)
        self.lease = None

    def user(self, sub="ops.meera", roles=("business_operator",)):
        return issue_token(SECRET, sub, list(roles))

    def new_lease(self):
        r = self.c.post("/v1/tasks", json={"goal": "process inbox"},
                        headers={"Authorization": f"Bearer {self.agent_token}", "X-On-Behalf-Of": self.user()})
        assert r.status_code == 200, r.text
        self.lease = r.json()
        return self.lease

    def call(self, tool, args, *, key=None, call_id=None, issued_at=None, lease=None, token="default", body=None):
        lease = lease or self.lease or self.new_lease()
        body = body or {"call_id": call_id or str(uuid.uuid4()), "task_id": lease["task_id"], "step_id": "s1",
                        "tool": tool, "args": args, "issued_at": issued_at or self.ctx.now().isoformat()}
        if key:
            body["idempotency_key"] = key
        headers = {"X-Lease": lease["lease_token"]}
        if token == "default":
            headers["Authorization"] = f"Bearer {self.agent_token}"
        elif token:
            headers["Authorization"] = f"Bearer {token}"
        r = self.c.post("/v1/tool-calls", json=body, headers=headers)
        return r.status_code, r.json()

    def pay(self, invoice="5105600031", amount=980000, key=None, **kw):
        return self.call("execute_payment", {"supplier_invoice": invoice, "fiscal_year": "2026", "amount_inr": amount},
                         key=key or f"pay:{invoice}:2026", **kw)

    def bank_change(self, **kw):
        args = {"supplier": "100045", "bank_account_holder_name": "ACME COMPONENTS PVT LTD", "bank_account": "123456789",
                "ifsc": "HDFC0000123", "reason": "letter", "source_message_id": "m1"}
        return self.call("update_supplier_bank", args, key=kw.pop("key", f"bank:{uuid.uuid4()}"), **kw)

    def freight(self, mode="AIR", cost=950000, days=2, **kw):
        return self.call("book_freight", {"purchase_order": "4500030", "mode": mode, "quoted_cost_inr": cost,
                                          "claimed_delay_days": days, "reason": "port closed", "source_message_id": "m1"},
                         key=kw.pop("key", f"frt:{uuid.uuid4()}"), **kw)


@pytest.fixture
def h(tmp_path):
    priv, pub = generate_keypair()
    settings = Settings(jwt_secret=SECRET, database_url=f"sqlite:///{tmp_path / 'gw.db'}", lease_signing_key=priv,
                        lease_public_key=pub, sandbox=True,
                        demo_passwords={"DEMO_PASSWORD_MEERA": "pw-meera", "DEMO_PASSWORD_ADMIN": "pw-admin",
                                        "DEMO_PASSWORD_PRESENTER": "pw-pres"})
    erp, oracles = FakeErp(), FakeOracles()
    app = create_app(settings, erp=erp, oracles=oracles)
    with TestClient(app) as client:
        yield Harness(client, erp, oracles, app)
