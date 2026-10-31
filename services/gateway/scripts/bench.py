"""Decision latency against in-process fakes (excludes network, model, oracle timeout).
Run from services/gateway: python -m scripts.bench"""
import statistics
import tempfile
import time
import uuid
from pathlib import Path

from fastapi.testclient import TestClient

from app.core.lease import generate_keypair
from app.main import create_app
from app.settings import Settings
from tests.conftest import FakeErp, FakeOracles, Harness

priv, pub = generate_keypair()
with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as d:
    app = create_app(Settings(jwt_secret="test-secret", database_url=f"sqlite:///{Path(d) / 'b.db'}",
                              lease_signing_key=priv, lease_public_key=pub), erp=FakeErp(), oracles=FakeOracles())
    with TestClient(app) as c:
        h = Harness(c, c.app.state.ctx.erp, c.app.state.ctx.oracles, app)
        h.new_lease()
        with h.ctx.session() as s:
            from app.db import Lease
            row = s.get(Lease, h.lease["lease_id"])
            row.scope = {**row.scope, "max_calls": 10_000}
            s.commit()
        lat = {"read": [], "invoice_deny": []}
        for _ in range(150):
            t = time.perf_counter(); h.call("get_purchase_order", {"purchase_order": "4500017"})
            lat["read"].append((time.perf_counter() - t) * 1000)
        for _ in range(150):  # DENY would suspend the lease; reset denials each loop
            with h.ctx.session() as s:
                row = s.get(Lease, h.lease["lease_id"]); row.denials = 0; row.status = "ACTIVE"; s.commit()
            t = time.perf_counter()
            h.call("post_supplier_invoice", {"supplier": "100045", "purchase_order": "4500021",
                   "supplier_invoice_ref": str(uuid.uuid4()), "invoice_date": "2026-10-30",
                   "items": [{"purchase_order_item": "10", "quantity": 100, "unit_price_inr": 12700}],
                   "gross_amount_inr": 1270000, "source_document_id": "d"}, key=str(uuid.uuid4()))
            lat["invoice_deny"].append((time.perf_counter() - t) * 1000)
        for k, v in lat.items():
            v.sort()
            print(f"{k}: n={len(v)} p50={statistics.median(v):.1f}ms p95={v[int(len(v) * .95)]:.1f}ms max={v[-1]:.1f}ms")
