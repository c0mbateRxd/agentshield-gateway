# Contract change requests

## CCR-G1 (Chandan, gateway): assumptions made because spec sections were missing or ambiguous
The pasted MASTER_SPEC ended inside 10.4; sections 11 (events) and 12 (ERP contract) were not available.
Gateway was built against the assumptions below. Pavan/Kirti: confirm or correct, gateway changes are one-line.

1. **ERP read paths** (`app/core/erp.py` READ_PATHS) are `/sim/v1/...`: inbox, documents/{id}, purchase-orders/{po}
   (+ /goods-receipts), suppliers/{s} (+ /bank, /purchase-orders), suppliers/by-domain/{d}, supplier-invoices[?supplier=],
   supplier-invoices/{fy}/{inv}. Writes: POST supplier-invoices, payments, suppliers/{s}/bank, freight-bookings,
   with `If-Match`, `Idempotency-Key`, `X-Sim-Profile`; 412 = ETag mismatch, 409 = duplicate. Also `/sim/v1/state-digest`, `/sim/v1/reset`.
2. **ERP fields the rules read**: PO header carries `YY1_AirFreightQuoteInr`, `YY1_SeaFreightPlannedInr`,
   `YY1_DelayPenaltyPerDayInr`, `YY1_PortCode`; invoices carry `items:[{PurchaseOrderItem, Quantity}]` (for R-INV-02
   previously-invoiced qty) and `Supplier`, `PurchaseOrder`, `Status` (POSTED|PAID|CANCELLED|DRAFT), `InvoiceGrossAmount`.
3. **ETag guarding**: payment and bank update send the supplier-bank ETag in `If-Match`; invoice posting and freight send the PO ETag.
4. **Oracle paths**: `POST /v1/penny-drop {account,ifsc}` -> `{holder_name}`; `GET /v1/gstin/{g}` -> `{legal_name,trade_name}`;
   `GET /v1/ais/{port}` -> `{port,berthed_today,threshold}` (disruption = berthed_today < threshold); `GET /v1/health`.
5. **Event envelope**: `{seq, ts, type, source, correlation_id, payload}`. Types emitted: task.created, lease.issued,
   lease.suspended, lease.revoked, toolcall.received, toolcall.replayed, decision.made, downstream.executed/failed,
   approval.requested/decided, message.flagged, task.completed, profile.changed, system.reset, audit.checkpoint.
6. **Lease scope from inbox**: for each unread message whose `from_domain` matches a supplier's `EmailDomain` in the ERP
   (and the supplier is in the operator's allowed set), scope = that supplier + all its POs (intersected with the operator's
   allowed POs). Messages are not parsed for PO numbers.
7. **R-INV-01 `inr_at_risk`** sums only offending lines, as qty x (claimed - PO price).
8. **R-PAY-01 supplier-not-in-lease** returns `DENY_OBJECT_NOT_IN_SCOPE` (spec text lists only NOT_PAYABLE / DUPLICATE).
9. **Idempotency** is global per key (not per lease) and stored only for ALLOW; HOLD/DENY are not cached so a retry after approval works.
10. `fiscal_year` is a string; `POST /v1/tasks` accepts optional `template` and `agent_id`; `decide` body is `{decision: APPROVE|REJECT, comment?}`.
11. VULNERABLE profile also skips the timestamp window (otherwise replayed captures expire after 60 s).
12. **R-BANK-01 weakness**: `token_set_ratio` scores a superset name ("ACME COMPONENTS TRADERS" vs "Acme Components") at 100,
    so an attacker can pass by appending words to the real name. Spec mandates it; propose also requiring `ratio >= 80`.
