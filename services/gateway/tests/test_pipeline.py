import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

from app.core import audit, pipeline
from app.core.auth import issue_token
from app.core.lease import generate_keypair
from app.db import Audit, Lease
from tests.conftest import SECRET, TODAY

INV_ITEM = {"purchase_order_item": "10", "quantity": 100, "unit_price_inr": 10000}


def post_invoice(h, price=10000, qty=100, **kw):
    gross = price * qty
    return h.call("post_supplier_invoice", {
        "supplier": "100045", "purchase_order": "4500021", "supplier_invoice_ref": f"INV-{uuid.uuid4()}",
        "invoice_date": "2026-10-30", "items": [{"purchase_order_item": "10", "quantity": qty, "unit_price_inr": price}],
        "gross_amount_inr": gross, "source_document_id": "d1"}, key=kw.pop("key", f"post:{uuid.uuid4()}"), **kw)


def reason(resp):
    return resp[1]["reason_code"]


# ---- auth + lease ---------------------------------------------------------------------------------------

def test_login_and_task_scope(h):
    r = h.c.post("/v1/auth/login", json={"username": "ops.meera", "password": "pw-meera"})
    assert r.status_code == 200 and r.json()["roles"] == ["business_operator"]
    assert h.c.post("/v1/auth/login", json={"username": "ops.meera", "password": "nope"}).status_code == 401
    lease = h.new_lease()
    # unknown domain (evil.example) did not widen scope; only ACME's objects are in the lease
    assert lease["scope"]["suppliers"] == ["100045"]
    assert lease["scope"]["purchase_orders"] == ["4500017", "4500021", "4500030"]
    assert "4500099" not in lease["scope"]["purchase_orders"]
    assert h.c.get(f"/v1/leases/{lease['lease_id']}",
                   headers={"Authorization": f"Bearer {h.user('soc.kavya', ('defender',))}"}).json()["status"] == "ACTIVE"


def test_task_requires_operator_on_behalf_of(h):
    r = h.c.post("/v1/tasks", json={"goal": "x"}, headers={
        "Authorization": f"Bearer {h.agent_token}", "X-On-Behalf-Of": h.user("redteam", ("attacker_sandbox",))})
    assert r.status_code == 403


def test_unauthenticated_agent(h):
    s, b = h.call("get_supplier", {"supplier": "100045"}, token=None)
    assert s == 401 and b["reason_code"] == "DENY_AGENT_UNAUTHENTICATED"
    s, b = h.call("get_supplier", {"supplier": "100045"}, token=h.user())  # user token, not agent
    assert s == 401


def test_read_allow_and_decision_shape(h):
    s, b = h.call("get_purchase_order", {"purchase_order": "4500017"})
    assert s == 200 and b["decision"] == "ALLOW" and b["reason_code"] == "ALLOW_OK"
    assert b["result"]["etag"] and b["safe_alternatives"] == []
    assert {c["name"] for c in b["checks"]} >= {"policy.hash", "agent.auth", "lease.signature", "scope"}


def test_document_text_truncated_and_marked(h):
    _, b = h.call("get_document_text", {"document_id": "d1"})
    assert len(b["result"]["text"]) == 4000 and b["result"]["truncated"] is True
    assert b["result"]["provenance"] == "external_email_attachment"


def test_lease_tamper_expired_revoked(h):
    lease = h.new_lease()
    body, sig = lease["lease_token"].split(".")
    forged = {**lease, "lease_token": f"{'A' if body[0] != 'A' else 'B'}{body[1:]}.{sig}"}
    assert reason(h.call("get_supplier", {"supplier": "100045"}, lease=forged)) == "DENY_LEASE_INVALID"
    assert reason(h.call("get_supplier", {"supplier": "100045"}, lease={**lease, "lease_token": "x.y"})) == "DENY_LEASE_INVALID"
    h.ctx.now = lambda: __import__("datetime").datetime.now(__import__("datetime").UTC) + timedelta(hours=1)
    assert reason(h.call("get_supplier", {"supplier": "100045"}, lease=lease)) == "DENY_LEASE_EXPIRED"
    h.ctx.now = lambda: __import__("datetime").datetime.now(__import__("datetime").UTC)
    lease2 = h.new_lease()
    h.c.post(f"/v1/leases/{lease2['lease_id']}/revoke", headers={"Authorization": f"Bearer {h.user()}"})
    assert reason(h.call("get_supplier", {"supplier": "100045"}, lease=lease2)) == "DENY_LEASE_REVOKED"


def test_denial_budget_suspends_lease(h):
    h.new_lease()
    bad = lambda: h.call("get_supplier", {"supplier": "999"})  # noqa: E731 - out of scope object
    assert [reason(bad()) for _ in range(2)] == ["DENY_OBJECT_NOT_IN_SCOPE"] * 2
    s, b = bad()
    assert b["reason_code"] == "DENY_DENIAL_BUDGET_EXHAUSTED" and b["decision"] == "DENY"
    assert reason(h.call("get_supplier", {"supplier": "100045"})) == "DENY_LEASE_SUSPENDED"
    assert any(e["type"] == "lease.suspended" for e in h.c.get(
        "/v1/events", headers={"Authorization": f"Bearer {h.user('soc.kavya', ('defender',))}"}).json())


# ---- nonce, timestamp, idempotency ----------------------------------------------------------------------

def test_nonce_reuse_and_write_replay(h):
    cid = str(uuid.uuid4())
    assert h.call("get_supplier", {"supplier": "100045"}, call_id=cid)[0] == 200
    s, b = h.call("get_supplier", {"supplier": "100045"}, call_id=cid)
    assert s == 409 and b["reason_code"] == "DENY_NONCE_REUSED"
    cid2 = str(uuid.uuid4())
    s1, b1 = h.pay(call_id=cid2)
    s2, b2 = h.pay(call_id=cid2)
    assert (s1, s2) == (200, 200) and b2["idempotent_replay"] is True and b2["decision_id"] == b1["decision_id"]
    assert len(h.erp.writes) == 1


def test_replayed_deny_stays_deny(h):
    lease = h.new_lease()
    args = {"supplier": "100045", "purchase_order": "4500021", "supplier_invoice_ref": "FIXED", "invoice_date": "2026-10-30",
            "items": [{"purchase_order_item": "10", "quantity": 100, "unit_price_inr": 12700}],
            "gross_amount_inr": 1270000, "source_document_id": "d"}
    cid = str(uuid.uuid4())
    first = h.call("post_supplier_invoice", args, key="post:fixed", call_id=cid, lease=lease)
    again = h.call("post_supplier_invoice", args, key="post:fixed", call_id=cid, lease=lease)
    assert first[0] == 403 and again[0] == 403  # a replayed DENY must not turn into 200
    assert again[1]["idempotent_replay"] is True and again[1]["decision_id"] == first[1]["decision_id"]
    assert h.erp.writes == []


def test_stale_and_bad_timestamp(h):
    old = (h.ctx.now() - timedelta(seconds=120)).isoformat()
    assert reason(h.call("get_supplier", {"supplier": "100045"}, issued_at=old)) == "DENY_STALE_REQUEST"
    assert reason(h.call("get_supplier", {"supplier": "100045"}, issued_at="2026-10-30T10:00:00")) == "DENY_SCHEMA_INVALID"
    near = (h.ctx.now() - timedelta(seconds=30)).isoformat()
    assert h.call("get_supplier", {"supplier": "100045"}, issued_at=near)[0] == 200


def test_idempotency_same_key(h):
    s1, b1 = h.pay(key="pay:A")
    s2, b2 = h.pay(key="pay:A")  # new call_id, same key, same request
    assert s2 == 200 and b2["idempotent_replay"] is True and b2["decision_id"] == b1["decision_id"]
    s3, b3 = h.pay(invoice="5105600032", amount=3870000, key="pay:A")  # same key, different request
    assert s3 == 409 and b3["reason_code"] == "DENY_NONCE_REUSED"
    assert len(h.erp.writes) == 1


def test_write_requires_idempotency_key_and_schema(h):
    lease = h.new_lease()
    body = {"call_id": str(uuid.uuid4()), "task_id": lease["task_id"], "step_id": "s", "tool": "execute_payment",
            "args": {"supplier_invoice": "5105600031", "fiscal_year": "2026", "amount_inr": 980000},
            "issued_at": h.ctx.now().isoformat()}
    assert reason(h.call("", {}, body=body)) == "DENY_SCHEMA_INVALID"  # no idempotency_key
    assert reason(h.call("execute_payment", {"supplier_invoice": "1", "amount_inr": "x", "extra": 1}, key="k")) == "DENY_SCHEMA_INVALID"
    h.new_lease()  # fresh lease: three denials above would otherwise hit the denial budget
    assert reason(h.call("", {}, body={"tool": "x"})) == "DENY_SCHEMA_INVALID"  # bad envelope
    assert reason(h.call("hack_erp", {})) == "DENY_TOOL_NOT_IN_SCOPE"


# ---- scope ----------------------------------------------------------------------------------------------

def test_scope_violations(h):
    lease = h.new_lease()
    assert reason(h.call("get_purchase_order", {"purchase_order": "4500099"})) == "DENY_OBJECT_NOT_IN_SCOPE"
    s = h.ctx.session()
    with s as db:
        row = db.get(Lease, lease["lease_id"])
        row.scope = {**row.scope, "tools": ["get_supplier"], "max_calls": 99}
        db.commit()
    assert reason(h.call("get_purchase_order", {"purchase_order": "4500017"})) == "DENY_TOOL_NOT_IN_SCOPE"


def test_amount_exceeds_lease_and_budget(h):
    assert reason(h.pay(amount=5000001)) == "DENY_AMOUNT_EXCEEDS_LEASE"
    h2 = h.new_lease()
    with h.ctx.session() as db:
        row = db.get(Lease, h2["lease_id"])
        row.calls_used = row.scope["max_calls"]
        db.commit()
    assert reason(h.call("get_supplier", {"supplier": "100045"})) == "DENY_CALL_BUDGET_EXHAUSTED"


# ---- invoice rules end to end ---------------------------------------------------------------------------

def test_invoice_allow_and_poisoned_pdf(h):
    s, b = post_invoice(h)
    assert s == 200 and b["result"]["Status"] == "POSTED"
    s, b = post_invoice(h, price=12700)
    assert s == 403 and b["reason_code"] == "DENY_PRICE_VARIANCE" and b["inr_at_risk"] == 270000
    assert b["formula"] == "invoice ₹12,700 > PO ₹10,000 × 1.05 = ₹10,500 (+27.0%)"
    assert b["rule_id"] == "R-INV-01" and len(h.erp.writes) == 1


def test_invoice_qty_and_amount_rules(h):
    assert reason(post_invoice(h, qty=101)) == "DENY_QTY_EXCEEDS_GR"
    lease = h.new_lease()
    s, b = h.call("post_supplier_invoice", {
        "supplier": "100045", "purchase_order": "4500021", "supplier_invoice_ref": "X", "invoice_date": "2026-10-30",
        "items": [INV_ITEM], "gross_amount_inr": 1, "source_document_id": "d"}, key="k1", lease=lease)
    assert b["reason_code"] == "DENY_AMOUNT_MISMATCH"


# ---- payment rules --------------------------------------------------------------------------------------

def test_payment_allow_then_duplicate_distinct_keys(h):
    s, b = h.pay(key="pay:one")
    assert s == 200 and b["result"]["Status"] == "PAID"
    s, b = h.pay(key="pay:two")
    assert s == 409 and b["reason_code"] == "DENY_DUPLICATE_PAYMENT" and b["inr_at_risk"] == 980000


def test_payment_not_payable_and_mismatch(h):
    assert reason(h.pay(invoice="5105600041", amount=100000)) == "DENY_INVOICE_NOT_PAYABLE"
    assert reason(h.pay(invoice="9999999999", amount=1)) == "DENY_INVOICE_NOT_PAYABLE"
    h.new_lease()  # two denials so far; a third would suspend this lease
    assert reason(h.pay(amount=979999)) == "DENY_AMOUNT_MISMATCH"
    assert h.erp.writes == []


def test_cooling_off_hold_and_approval_releases(h):
    h.erp.banks["100045"]["ValidityStartDate"] = TODAY
    s, b = h.pay()
    assert s == 202 and b["reason_code"] == "HOLD_BANK_COOLING_OFF" and b["approval_id"]
    assert h.erp.writes == []
    arjun = {"Authorization": f"Bearer {h.user('approver.arjun', ('business_approver',))}"}
    pending = h.c.get("/v1/approvals", headers=arjun).json()
    assert [a["approval_id"] for a in pending] == [b["approval_id"]]
    r = h.c.post(f"/v1/approvals/{b['approval_id']}/decide", json={"decision": "APPROVE"}, headers=arjun).json()
    assert r["status"] == "APPROVED" and r["result"]["decision"] == "ALLOW" and len(h.erp.writes) == 1
    again = h.c.post(f"/v1/approvals/{b['approval_id']}/decide", json={"decision": "APPROVE"}, headers=arjun).json()
    assert again["result"]["decision_id"] == r["result"]["decision_id"] and len(h.erp.writes) == 1
    # operator cannot approve
    assert h.c.post(f"/v1/approvals/{b['approval_id']}/decide", json={"decision": "APPROVE"},
                    headers={"Authorization": f"Bearer {h.user()}"}).status_code == 403


def test_approval_never_clears_deny(h):
    h.erp.banks["100045"]["ValidityStartDate"] = TODAY
    _, b = h.pay()
    h.erp.invoices[("2026", "5105600031")]["Status"] = "PAID"  # state changed while waiting for the approver
    arjun = {"Authorization": f"Bearer {h.user('approver.arjun', ('business_approver',))}"}
    r = h.c.post(f"/v1/approvals/{b['approval_id']}/decide", json={"decision": "APPROVE"}, headers=arjun).json()
    assert r["result"]["reason_code"] == "DENY_DUPLICATE_PAYMENT" and h.erp.writes == []


def test_reject_approval_does_not_execute(h):
    h.erp.banks["100045"]["ValidityStartDate"] = TODAY
    _, b = h.pay()
    arjun = {"Authorization": f"Bearer {h.user('approver.arjun', ('business_approver',))}"}
    r = h.c.post(f"/v1/approvals/{b['approval_id']}/decide", json={"decision": "REJECT"}, headers=arjun).json()
    assert r["status"] == "REJECTED" and h.erp.writes == []


def test_bank_change_denied_then_payment_on_hold(h):
    h.oracles.holder = "RAJESH TRADERS"
    s, b = h.bank_change()
    assert s == 403 and b["reason_code"] == "DENY_BANK_NAME_MISMATCH" and b["inr_at_risk"] == 4850000
    assert "₹48,50,000" in b["formula"] and h.erp.writes == []
    s, b = h.pay()
    assert s == 202 and b["reason_code"] == "HOLD_BANK_CHANGE_UNDER_REVIEW" and b["inr_at_risk"] == 980000


# ---- bank / oracle --------------------------------------------------------------------------------------

def test_bank_change_allow_partial_and_oracle_down(h):
    s, b = h.bank_change()
    assert s == 200 and b["result"]["Status"] == "UPDATED"
    h.oracles.holder = "ACMEE COMPONENT SALES"
    assert reason(h.bank_change()) == "HOLD_BANK_NAME_PARTIAL"
    h.oracles.fail = True
    s, b = h.bank_change()
    assert s == 202 and b["reason_code"] == "HOLD_ORACLE_UNAVAILABLE"
    assert any(c["name"] == "oracle.bank" and c["result"] == "error" for c in b["checks"])


# ---- freight --------------------------------------------------------------------------------------------

def test_freight_paths(h):
    s, b = h.freight(days=2)
    assert s == 403 and b["reason_code"] == "DENY_FREIGHT_UNECONOMIC" and b["inr_at_risk"] == 800000
    h.oracles.berthed = 9  # AIS says the port is open
    assert reason(h.freight(days=10)) == "DENY_SIGNAL_CONTRADICTED"
    h.oracles.berthed = 1
    s, b = h.freight(days=10)
    assert s == 202 and b["reason_code"] == "HOLD_AMOUNT_NEEDS_APPROVAL"
    arjun = {"Authorization": f"Bearer {h.user('approver.arjun', ('business_approver',))}"}
    r = h.c.post(f"/v1/approvals/{b['approval_id']}/decide", json={"decision": "APPROVE"}, headers=arjun).json()
    assert r["result"]["decision"] == "ALLOW" and len(h.erp.writes) == 1
    assert h.freight(mode="SEA", cost=150000, days=0)[0] == 200
    h.oracles.fail = True
    assert reason(h.freight(days=10)) == "HOLD_ORACLE_UNAVAILABLE"


# ---- fail-closed behaviours -----------------------------------------------------------------------------

def test_etag_race_concurrent_modification(h):
    def bank_changes_mid_flight(erp):
        erp.bump("bank", "100045")
        erp.before_write = None
    h.erp.before_write = bank_changes_mid_flight
    s, b = h.pay()
    assert s == 409 and b["reason_code"] == "DENY_CONCURRENT_MODIFICATION" and h.erp.writes == []


def test_erp_down_denies(h):
    h.new_lease()
    h.erp.down = True
    s, b = h.pay()
    assert s == 503 and b["reason_code"] == "DENY_DEPENDENCY_UNAVAILABLE" and b["decision"] == "DENY"


def test_policy_error_denies_never_allows(h):
    h.new_lease()
    h.ctx.settings.test_inject_policy_error = True
    s, b = h.pay()
    assert s == 403 and b["reason_code"] == "DENY_POLICY_ERROR" and h.erp.writes == []
    assert "error id" in b["message"]
    h.erp.read = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom"))
    h.ctx.settings.test_inject_policy_error = False
    s, b = h.call("get_supplier", {"supplier": "100045"})
    assert b["reason_code"] == "DENY_POLICY_ERROR"


def test_unexpected_erp_data_shape_denies(h):
    h.erp.invoices[("2026", "5105600031")].pop("InvoiceGrossAmount")
    s, b = h.pay()
    assert b["decision"] == "DENY" and h.erp.writes == []


# ---- concurrency ----------------------------------------------------------------------------------------

def _parallel_pay(h, keys, lease_per_call=False):
    shared = None if lease_per_call else h.new_lease()
    leases = [shared or h.new_lease() for _ in keys]
    ctx = h.ctx

    def one(arg):
        key, lease = arg
        body = {"call_id": str(uuid.uuid4()), "task_id": lease["task_id"], "step_id": "s", "tool": "execute_payment",
                "idempotency_key": key, "issued_at": ctx.now().isoformat(),
                "args": {"supplier_invoice": "5105600031", "fiscal_year": "2026", "amount_inr": 980000}}
        return pipeline.handle(ctx, h.agent_token, lease["lease_token"], body)
    with ThreadPoolExecutor(20) as ex:
        return list(ex.map(one, zip(keys, leases)))


def test_20_parallel_payments_same_key_executes_once(h):
    out = _parallel_pay(h, ["pay:same"] * 20)
    assert len(h.erp.writes) == 1
    assert [(s, b["reason_code"]) for s, b in out if s != 200] == []
    assert sum(1 for _, b in out if not b["idempotent_replay"]) == 1


def test_20_parallel_payments_distinct_keys_one_allow(h):
    out = _parallel_pay(h, [f"pay:{i}" for i in range(20)], lease_per_call=True)  # own lease each: no denial budget noise
    assert len(h.erp.writes) == 1
    assert sorted(b["reason_code"] for _, b in out) == ["ALLOW_OK"] + ["DENY_DUPLICATE_PAYMENT"] * 19


# ---- profiles + sandbox ---------------------------------------------------------------------------------

def test_default_profile_protected(h):
    assert h.ctx.profile == "PROTECTED" and h.erp.profile == "PROTECTED"
    r = h.c.get("/v1/admin/profile", headers={"Authorization": f"Bearer {h.user('admin', ('admin',))}"})
    assert r.json()["profile"] == "PROTECTED"


def test_admin_routes_absent_without_sandbox(tmp_path):
    from fastapi.testclient import TestClient

    from app.main import create_app
    from app.settings import Settings
    from tests.conftest import FakeErp, FakeOracles
    priv, pub = generate_keypair()
    app = create_app(Settings(jwt_secret=SECRET, database_url=f"sqlite:///{tmp_path / 'x.db'}",
                              lease_signing_key=priv, lease_public_key=pub),
                     erp=FakeErp(), oracles=FakeOracles())
    c = TestClient(app)
    assert c.post("/v1/admin/profile", json={"profile": "VULNERABLE"},
                  headers={"Authorization": f"Bearer {issue_token(SECRET, 'admin', ['admin'])}"}).status_code == 404
    assert c.post("/v1/auth/login", json={"username": "presenter", "password": "x"}).status_code == 401


def test_vulnerable_profile_bypasses_and_reset_restores(h):
    admin = {"Authorization": f"Bearer {h.user('admin', ('admin',))}"}
    h.oracles.holder = "RAJESH TRADERS"
    assert reason(h.bank_change()) == "DENY_BANK_NAME_MISMATCH"
    assert h.c.post("/v1/admin/profile", json={"profile": "VULNERABLE"}, headers=admin).json()["profile"] == "VULNERABLE"
    assert h.erp.profile == "VULNERABLE"
    s, b = h.bank_change()
    assert s == 200 and h.erp.writes[-1][0] == "update_supplier_bank"  # rules bypassed
    cid = str(uuid.uuid4())
    assert h.pay(call_id=cid, key="k1")[0] == 200
    caps = h.c.get("/v1/sandbox/captures", headers={"Authorization": f"Bearer {h.user('redteam', ('attacker_sandbox',))}"}).json()
    assert caps and "lease_token" not in str(caps) and caps[0]["request"]["tool"]
    assert h.c.post("/v1/admin/reset", headers=admin).json()["profile"] == "PROTECTED"
    assert h.ctx.profile == "PROTECTED" and h.c.get(f"/v1/leases/{h.lease['lease_id']}", headers=admin).json()["status"] == "REVOKED"


# ---- events + audit -------------------------------------------------------------------------------------

def test_audit_chain_verify_and_tamper(h):
    for _ in range(3):
        h.call("get_supplier", {"supplier": "100045"})
    kav = {"Authorization": f"Bearer {h.user('soc.kavya', ('defender',))}"}
    assert h.c.get("/v1/audit/verify", headers=kav).json() == {"ok": True, "entries": 3, "first_bad_seq": None}
    with h.ctx.session() as db:
        row = db.get(Audit, 2)
        row.payload_canonical = row.payload_canonical.replace("ALLOW", "DENY")
        db.commit()
    assert h.c.get("/v1/audit/verify", headers=kav).json() == {"ok": False, "entries": 2, "first_bad_seq": 2}
    assert audit.head(h.ctx)["seq"] == 3


def test_events_ingest_catchup_and_filter(h):
    kav = {"Authorization": f"Bearer {h.user('soc.kavya', ('defender',))}"}
    svc = {"Authorization": f"Bearer {issue_token(SECRET, 'svc:agent', ['event_emitter'])}"}
    assert h.c.post("/v1/events/ingest", json={"type": "agent.step", "correlation_id": "T1", "payload": {"n": 1}},
                    headers=svc).json()["seq"] >= 1
    assert h.c.post("/v1/events/ingest", json={"type": "x", "payload": {}}, headers=kav).status_code == 403
    h.call("get_supplier", {"supplier": "100045"})
    allev = h.c.get("/v1/events", headers=kav).json()
    seqs = [e["seq"] for e in allev]
    assert seqs == sorted(seqs) and len(set(seqs)) == len(seqs)
    types = [e["type"] for e in allev]
    assert types.index("task.created") < types.index("toolcall.received") < types.index("decision.made")
    missed = h.c.get(f"/v1/events?after={seqs[2]}", headers=kav).json()
    assert [e["seq"] for e in missed] == seqs[3:]
    assert [e["type"] for e in h.c.get("/v1/events?correlation_id=T1", headers=kav).json()] == ["agent.step"]


def test_sse_stream_delivers_and_resumes(h):
    token = h.user("soc.kavya", ("defender",))
    h.call("get_supplier", {"supplier": "100045"})
    with h.c.stream("GET", f"/v1/events/stream?token={token}&after=0") as r:
        assert r.status_code == 200
        ids = []
        for line in r.iter_lines():
            if line.startswith("id:"):
                ids.append(int(line.split(":")[1]))
            if len(ids) >= 3:
                break
    assert ids == sorted(ids)
    assert h.c.get("/v1/events/stream?token=bad").status_code == 401
