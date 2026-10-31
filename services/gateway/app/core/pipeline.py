"""The ordered tool-call pipeline (spec 10.1 to 10.3). Every non-ALLOW outcome is a `Stop`; the only path to
ALLOW is falling off the end of `_execute`. Any unexpected exception becomes DENY_POLICY_ERROR."""
import uuid
from datetime import datetime, timedelta

import structlog
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError

from app.core import audit, events
from app.core.auth import decode_token
from app.core.canonical import canonical, sha256_hex
from app.core.erp import ErpConflict, ErpNotFound, ErpUnavailable
from app.core.lease import LeaseInvalid
from app.core.oracles import OracleError
from app.core.reasons import ReasonCode as R
from app.core.reasons import http_status, kind_of
from app.core.rules import RuleInput, evaluate
from app.core.tools import KIND, SCHEMAS, envelope_errors, schema_errors
from app.db import Approval, Decision, Idempotency, Lease, Nonce, Task

log = structlog.get_logger()
SAFE_ALTERNATIVES = ["request_human_approval", "flag_suspicious_message", "skip_step", "abort_task"]
LEASE_STATUS_CODE = {"REVOKED": R.DENY_LEASE_REVOKED, "SUSPENDED": R.DENY_LEASE_SUSPENDED,
                     "EXPIRED": R.DENY_LEASE_EXPIRED}


class Stop(Exception):
    def __init__(self, code: R, message: str = "", rule_id: str | None = None, risk: int = 0,
                 formula: str | None = None):
        super().__init__(message)
        self.code, self.message, self.rule_id, self.risk, self.formula = code, message, rule_id, risk, formula


class Replay(Exception):
    """Return a stored response without re-executing. `status` is the stored HTTP status (a replayed DENY stays 403)."""

    def __init__(self, response: dict, status: int = 200):
        self.response, self.status = response, status


class Call:
    """Per-request state."""

    def __init__(self, ctx, body, override_holds: bool = False):
        self.ctx = ctx
        self.decision_id = str(uuid.uuid4())
        self.body = body if isinstance(body, dict) else {}
        self.tool = self.body.get("tool") if isinstance(self.body.get("tool"), str) else None
        self.args = self.body.get("args") if isinstance(self.body.get("args"), dict) else {}
        self.idem = self.body.get("idempotency_key")
        self.checks: list[dict] = []
        self.lease: dict | None = None
        self.correlation = self.body.get("task_id")
        self.override_holds = override_holds
        self.count_call = True
        self.lease_ok = False
        self.agent: str | None = None
        self.approval_id: str | None = None
        self.held = None  # per-object lock; held until the decision (and idempotency row) is persisted
        self.check("policy.hash", "pass", ctx.policy.hash)

    def check(self, name: str, result: str, detail: str = ""):
        self.checks.append({"name": name, "result": result, "detail": detail})

    @property
    def request_hash(self) -> str:
        return sha256_hex(canonical({"tool": self.tool, "args": self.args, "idempotency_key": self.idem}))

    @property
    def is_write(self) -> bool:
        return KIND.get(self.tool) == "write"


# ---------------------------------------------------------------------------------------------------------
# entry points

def _guard(call: Call, run) -> tuple[int, dict]:
    """Run `run()`; every non-ALLOW outcome is a Stop, any unexpected error is DENY_POLICY_ERROR.
    The write lock taken in _execute is released only after finalize() has stored the decision and
    idempotency row, so a waiting duplicate sees the stored response instead of a half-finished state."""
    try:
        return _guard_inner(call, run)
    finally:
        if call.held:
            call.held.release()
            call.held = None


def _guard_inner(call: Call, run) -> tuple[int, dict]:
    try:
        return finalize(call, R.ALLOW_OK, "Allowed", result=run())
    except Replay as r:
        events.emit(call.ctx, "toolcall.replayed", call.correlation, {"decision_id": r.response["decision_id"]})
        return r.status, {**r.response, "idempotent_replay": True}
    except Stop as st:
        try:
            return finalize(call, st.code, st.message, st.rule_id, st.risk, st.formula)
        except Exception:
            return _policy_error(call)
    except Exception:
        return _policy_error(call)


def handle(ctx, agent_token: str | None, lease_token: str | None, body) -> tuple[int, dict]:
    call = Call(ctx, body)

    def run():
        _authenticate(call, agent_token)
        _check_lease(call, lease_token)
        _envelope(call)
        events.emit(ctx, "toolcall.received", call.correlation,
                    {"decision_id": call.decision_id, "tool": call.tool, "call_id": call.body.get("call_id"),
                     "lease_id": call.lease["lease_id"]})
        _nonce_and_idempotency(call)
        _timestamp(call)
        _schema(call)
        _scope(call)
        return _execute(call)

    return _guard(call, run)


def rerun_approved(ctx, orig: Decision, lease: dict) -> tuple[int, dict]:
    """Approval of a HOLD: re-run the stored call from the ERP-fetch step with HOLD reasons cleared.
    DENY rules still apply. Lease must still be ACTIVE (expiry is tolerated; approvals take time)."""
    body = {"call_id": orig.call_id, "idempotency_key": orig.idempotency_key, "task_id": orig.task_id,
            "step_id": orig.step_id, "tool": orig.tool, "args": orig.args}
    call = Call(ctx, body, override_holds=True)
    call.count_call, call.lease, call.lease_ok = False, lease, True
    call.agent, call.correlation = lease["agent_id"], lease["task_id"]

    def run():
        if lease["status"] != "ACTIVE":
            call.lease_ok = False
            raise Stop(LEASE_STATUS_CODE.get(lease["status"], R.DENY_LEASE_INVALID), f"Lease is {lease['status']}")
        return _execute(call)

    return _guard(call, run)


def _policy_error(call: Call) -> tuple[int, dict]:
    error_id = str(uuid.uuid4())
    log.error("policy_error", error_id=error_id, decision_id=call.decision_id, tool=call.tool, exc_info=True)
    try:
        return finalize(call, R.DENY_POLICY_ERROR, f"Internal policy error (error id {error_id})")
    except Exception:
        log.error("finalize_failed", error_id=error_id, exc_info=True)
        body = _response(call, R.DENY_POLICY_ERROR, f"Internal policy error (error id {error_id})")
        return 403, body


# ---------------------------------------------------------------------------------------------------------
# steps 1-6

def _authenticate(call: Call, token: str | None):
    try:
        claims = decode_token(call.ctx.settings.jwt_secret, token or "")
    except Exception:
        call.check("agent.auth", "fail", "missing or invalid token")
        raise Stop(R.DENY_AGENT_UNAUTHENTICATED, "Agent token missing or invalid") from None
    if "agent" not in claims["roles"]:
        call.check("agent.auth", "fail", "token lacks agent role")
        raise Stop(R.DENY_AGENT_UNAUTHENTICATED, "Token is not an agent token")
    call.agent = claims["sub"]
    call.check("agent.auth", "pass", claims["sub"])


def _check_lease(call: Call, token: str | None):
    ctx = call.ctx
    try:
        payload = ctx.keys.verify(token or "")
    except LeaseInvalid as e:
        call.check("lease.signature", "fail", str(e))
        raise Stop(R.DENY_LEASE_INVALID, "Lease signature or key id invalid", "R-GEN-01") from None
    call.check("lease.signature", "pass", f"kid={payload['kid']} lease_id={payload['lease_id']}")
    with ctx.session() as s:
        row = s.get(Lease, payload["lease_id"])
        if row is None or payload.get("agent_id") != call.agent or row.agent_id != call.agent:
            call.check("lease.binding", "fail", "unknown lease or agent mismatch")
            raise Stop(R.DENY_LEASE_INVALID, "Lease is not bound to this agent", "R-GEN-01")
        now_ts = ctx.now().timestamp()
        if row.status == "ACTIVE" and now_ts >= row.exp:
            row.status = "EXPIRED"
            s.commit()
        snap = {c: getattr(row, c) for c in ("lease_id", "task_id", "agent_id", "status", "scope", "exp",
                                             "calls_used", "denials", "issued_by")}
    call.lease = snap
    call.correlation = snap["task_id"]
    if snap["status"] != "ACTIVE":
        call.check("lease.status", "fail", snap["status"])
        raise Stop(LEASE_STATUS_CODE[snap["status"]], f"Lease is {snap['status']}", "R-GEN-01")
    if now_ts < payload["nbf"]:
        call.check("lease.nbf", "fail", "not yet valid")
        raise Stop(R.DENY_LEASE_INVALID, "Lease not yet valid", "R-GEN-01")
    call.check("lease.status", "pass", "ACTIVE")
    call.lease_ok = True


def _envelope(call: Call):
    errs = envelope_errors(call.body)
    if errs:
        call.check("envelope.schema", "fail", "; ".join(errs[:3]))
        raise Stop(R.DENY_SCHEMA_INVALID, "Request envelope is invalid", "R-GEN-03")
    if call.body["task_id"] != call.lease["task_id"]:
        call.check("envelope.task", "fail", "task_id does not match lease")
        raise Stop(R.DENY_LEASE_INVALID, "task_id does not match the lease", "R-GEN-01")


def _nonce_and_idempotency(call: Call):
    ctx = call.ctx
    if ctx.profile == "VULNERABLE":
        call.check("nonce", "skip", "VULNERABLE profile")
        return
    lease_id, call_id = call.lease["lease_id"], call.body["call_id"]
    with ctx.session() as s:
        s.add(Nonce(lease_id=lease_id, call_id=call_id, request_hash=call.request_hash))
        try:
            s.commit()
        except IntegrityError:
            s.rollback()
            prior = s.get(Nonce, (lease_id, call_id))
            first = s.scalars(select(Decision).where(Decision.lease_id == lease_id, Decision.call_id == call_id)
                              .order_by(Decision.created_at)).first()
            call.check("nonce", "fail", "call_id already used on this lease")
            if call.is_write and prior and prior.request_hash == call.request_hash and first:
                raise Replay(first.response, first.http_status)
            raise Stop(R.DENY_NONCE_REUSED, "call_id was already used on this lease", "R-GEN-03") from None
    call.check("nonce", "pass", call_id)
    if call.is_write:
        _check_idempotency(call)


def _check_idempotency(call: Call):
    if not call.idem or call.ctx.profile == "VULNERABLE":
        return
    with call.ctx.session() as s:
        row = s.get(Idempotency, call.idem)
    if row is None:
        call.check("idempotency", "pass", "new key")
        return
    if row.request_hash == call.request_hash:
        raise Replay(row.response)
    call.check("idempotency", "fail", "key reused with a different request")
    raise Stop(R.DENY_NONCE_REUSED, "Idempotency key reused with a different request", "R-GEN-04")


def _timestamp(call: Call):
    if call.ctx.profile == "VULNERABLE":
        call.check("timestamp", "skip", "VULNERABLE profile")
        return
    window = call.ctx.policy.rules["timestamp_window_s"]
    try:
        issued = datetime.fromisoformat(call.body["issued_at"].replace("Z", "+00:00"))
        skew = abs((call.ctx.now() - issued).total_seconds())
    except (ValueError, TypeError):
        call.check("timestamp", "fail", "unparseable or timezone-less issued_at")
        raise Stop(R.DENY_SCHEMA_INVALID, "issued_at must be an RFC3339 timestamp with timezone", "R-GEN-03") from None
    if skew > window:
        call.check("timestamp", "fail", f"skew {skew:.0f}s > {window}s")
        raise Stop(R.DENY_STALE_REQUEST, "Request timestamp outside the allowed window", "R-GEN-03")
    call.check("timestamp", "pass", f"skew {skew:.0f}s")


def _schema(call: Call):
    if call.tool not in SCHEMAS:
        call.check("tool.known", "fail", str(call.tool))
        raise Stop(R.DENY_TOOL_NOT_IN_SCOPE, f"Unknown tool {call.tool!r}", "R-GEN-02")
    errs = schema_errors(call.tool, call.args)
    if call.is_write and not call.idem:
        errs.append("idempotency_key is required for write tools")
    if errs:
        call.check("args.schema", "fail", "; ".join(errs[:3]))
        raise Stop(R.DENY_SCHEMA_INVALID, "Arguments do not match the tool schema", "R-GEN-03")
    call.check("args.schema", "pass", call.tool)


def _scope(call: Call):
    if call.ctx.profile == "VULNERABLE":
        call.check("scope", "skip", "VULNERABLE profile: broad static scope")
        return
    scope, a = call.lease["scope"], call.args
    if call.tool not in scope["tools"]:
        call.check("scope.tool", "fail", call.tool)
        raise Stop(R.DENY_TOOL_NOT_IN_SCOPE, f"Tool {call.tool} is not in the lease", "R-GEN-02")
    for key, allowed in (("supplier", "suppliers"), ("purchase_order", "purchase_orders")):
        if key in a and a[key] not in scope[allowed]:
            call.check("scope.object", "fail", f"{key}={a[key]}")
            raise Stop(R.DENY_OBJECT_NOT_IN_SCOPE, f"{key} {a[key]} is not in the lease scope", "R-GEN-02")
    for key in ("amount_inr", "gross_amount_inr"):
        if key in a and a[key] > scope["max_payment_inr"]:
            call.check("scope.amount", "fail", f"{a[key]} > {scope['max_payment_inr']}")
            raise Stop(R.DENY_AMOUNT_EXCEEDS_LEASE, "Amount exceeds the lease ceiling", "R-GEN-02", a[key])
    if call.lease["calls_used"] >= scope["max_calls"]:
        call.check("scope.budget", "fail", f"{call.lease['calls_used']} >= {scope['max_calls']}")
        raise Stop(R.DENY_CALL_BUDGET_EXHAUSTED, "Lease call budget exhausted", "R-GEN-01")
    call.check("scope", "pass", "tool, objects, amount, budget")


# ---------------------------------------------------------------------------------------------------------
# steps 7-10

def _target_key(call: Call) -> str:
    a = call.args
    return {"execute_payment": lambda: f"inv:{a['fiscal_year']}:{a['supplier_invoice']}",
            "post_supplier_invoice": lambda: f"invref:{a['supplier_invoice_ref']}",
            "update_supplier_bank": lambda: f"sup:{a['supplier']}",
            "book_freight": lambda: f"po:{a['purchase_order']}"}[call.tool]()


def _execute(call: Call) -> dict:
    ctx = call.ctx
    if KIND[call.tool] == "control":
        return _control(call)
    if KIND[call.tool] == "read":
        return _read(call)
    call.held = ctx.lock(_target_key(call))
    call.held.acquire()
    if not call.override_holds:
        _check_idempotency(call)
    return _write(call)


def _erp_read(call: Call, kind: str, optional: bool = False, **params):
    try:
        data, etag = call.ctx.erp.read(kind, **params)
        call.check(f"erp.read.{kind}", "pass", f"etag={etag}")
        return data, etag
    except ErpNotFound:
        call.check(f"erp.read.{kind}", "fail", "not found")
        if optional:
            return None, None
        raise Stop(R.DENY_OBJECT_NOT_IN_SCOPE, f"{kind} not found in ERP", "R-GEN-02") from None
    except ErpUnavailable as e:
        call.check(f"erp.read.{kind}", "error", str(e))
        raise Stop(R.DENY_DEPENDENCY_UNAVAILABLE, "ERP is unavailable") from None


def _read(call: Call) -> dict:
    t, a = call.tool, call.args
    scope_suppliers = call.lease["scope"]["suppliers"]
    vuln = call.ctx.profile == "VULNERABLE"
    if t == "read_inbox":
        return _erp_read(call, "inbox", unread_only=a.get("unread_only", True))[0]
    if t == "get_document_text":
        d, _ = _erp_read(call, "document", document_id=a["document_id"])
        text = d.get("text", "")
        return {"document_id": d.get("document_id", a["document_id"]), "filename": d.get("filename"),
                "text": text[:4000], "provenance": "external_email_attachment", "truncated": len(text) > 4000}
    if t == "get_purchase_order":
        d, etag = _erp_read(call, "purchase_order", purchase_order=a["purchase_order"])
        return {**d, "etag": etag}
    if t == "get_goods_receipts":
        return _erp_read(call, "goods_receipts", purchase_order=a["purchase_order"])[0]
    if t in ("get_supplier", "get_supplier_bank"):
        d, etag = _erp_read(call, "supplier" if t == "get_supplier" else "supplier_bank", supplier=a["supplier"])
        return {**d, "etag": etag}
    if t == "list_open_invoices":
        d, _ = _erp_read(call, "invoices", supplier=a.get("supplier"))
        inv = [i for i in d.get("invoices", []) if i.get("Status") == "POSTED"
               and (vuln or i.get("Supplier") in scope_suppliers)]
        return {"invoices": inv}
    raise Stop(R.DENY_POLICY_ERROR, f"No read handler for {t}")


def _control(call: Call) -> dict:
    ctx, a = call.ctx, call.args
    if call.tool == "flag_suspicious_message":
        events.emit(ctx, "message.flagged", call.correlation, {"message_id": a["message_id"], "reason": a["reason"]})
        return {"flagged": True}
    if call.tool == "request_human_approval":
        approval_id = _new_approval(call, a["action_summary"], a["reason"])
        call.approval_id = approval_id
        return {"approval_id": approval_id, "status": "PENDING"}
    with ctx.session() as s:  # complete_task
        task = s.get(Task, call.lease["task_id"])
        if task:
            task.status = "COMPLETED"
            s.commit()
    events.emit(ctx, "task.completed", call.correlation, {"summary": a["summary"]})
    return {"task_status": "COMPLETED"}


def _new_approval(call: Call, summary: str, reason: str) -> str:
    approval_id = str(uuid.uuid4())
    with call.ctx.session() as s:
        s.add(Approval(approval_id=approval_id, decision_id=call.decision_id,
                       lease_id=call.lease["lease_id"], summary=summary, reason=reason))
        s.commit()
    events.emit(call.ctx, "approval.requested", call.correlation,
                {"approval_id": approval_id, "decision_id": call.decision_id, "summary": summary})
    return approval_id


def _gather(call: Call) -> tuple[dict, dict, str | None]:
    """Step 7 (+ oracle inputs for step 9): authoritative ERP state, history, etag to guard the write with."""
    ctx, a, t = call.ctx, call.args, call.tool
    erp, extra, etag = {}, {"oracle": {}, "history": {}}, None
    if t == "post_supplier_invoice":
        po, etag = _erp_read(call, "purchase_order", purchase_order=a["purchase_order"])
        if po.get("Supplier") != a["supplier"]:
            call.check("erp.po_supplier", "fail", f"PO supplier {po.get('Supplier')} != {a['supplier']}")
            raise Stop(R.DENY_OBJECT_NOT_IN_SCOPE, "Supplier does not match the purchase order", "R-INV-01")
        erp["purchase_order"] = po
        erp["goods_receipts"], _ = _erp_read(call, "goods_receipts", purchase_order=a["purchase_order"])
        invs, _ = _erp_read(call, "invoices", supplier=a["supplier"])
        erp["invoices"] = {"invoices": [i for i in invs.get("invoices", [])
                                        if i.get("PurchaseOrder") == a["purchase_order"]]}
    elif t == "execute_payment":
        inv, _ = _erp_read(call, "invoice", optional=True, fiscal_year=a["fiscal_year"],
                           supplier_invoice=a["supplier_invoice"])
        erp["invoice"] = inv
        if inv is not None:
            erp["bank"], etag = _erp_read(call, "supplier_bank", supplier=inv["Supplier"])
            cutoff = ctx.now() - timedelta(hours=ctx.policy.rules["bank_change_lookback_hours"])
            with ctx.session() as s:
                rows = s.scalars(select(Decision).where(Decision.tool == "update_supplier_bank",
                                                        Decision.decision != "ALLOW"))
                n = sum(1 for d in rows if (d.args or {}).get("supplier") == inv["Supplier"]
                        and d.created_at.replace(tzinfo=cutoff.tzinfo) >= cutoff)
            extra["history"]["recent_bank_decisions"] = n
    elif t == "update_supplier_bank":
        erp["supplier"], _ = _erp_read(call, "supplier", supplier=a["supplier"])
        erp["invoices"], _ = _erp_read(call, "invoices", supplier=a["supplier"])
        _, etag = _erp_read(call, "supplier_bank", supplier=a["supplier"])
        try:
            extra["oracle"] = {"penny_drop": ctx.oracles.penny_drop(a["bank_account"], a["ifsc"]),
                               "gstin": ctx.oracles.gstin(erp["supplier"]["GSTIN"])}
            call.check("oracle.bank", "pass", "penny-drop + GSTIN")
        except OracleError as e:
            extra["oracle"] = {"error": str(e)}
            call.check("oracle.bank", "error", str(e))
    elif t == "book_freight":
        erp["purchase_order"], etag = _erp_read(call, "purchase_order", purchase_order=a["purchase_order"])
        if a["mode"] == "AIR":
            try:
                extra["oracle"] = {"ais": ctx.oracles.ais(erp["purchase_order"]["YY1_PortCode"])}
                call.check("oracle.ais", "pass", "AIS")
            except OracleError as e:
                extra["oracle"] = {"error": str(e)}
                call.check("oracle.ais", "error", str(e))
    return erp, extra, etag


def _write(call: Call) -> dict:
    ctx, a = call.ctx, call.args
    vuln = ctx.profile == "VULNERABLE"
    etag = None
    if vuln:
        call.check("rules", "skip", "VULNERABLE profile")
    else:
        if ctx.settings.test_inject_policy_error:
            raise RuntimeError("injected policy error (test flag)")
        erp, extra, etag = _gather(call)
        inp = RuleInput(args=a, erp=erp, cfg=ctx.policy.rules, scope=call.lease["scope"],
                        today=ctx.now().date(), oracle=extra["oracle"], history=extra["history"])
        first_fail = None
        for o in evaluate(call.tool, inp):
            call.check(o.rule_id, "skip" if o.skipped else ("pass" if o.ok else "fail"), o.formula or o.message)
            if not o.ok and first_fail is None:
                first_fail = o
        if first_fail and not (call.override_holds and kind_of(first_fail.reason) == "HOLD"):
            raise Stop(first_fail.reason, first_fail.message, first_fail.rule_id, first_fail.inr_at_risk,
                       first_fail.formula)
        if first_fail:
            call.check("approval.override", "pass", f"{first_fail.reason.value} cleared by approver")
    try:
        result = ctx.erp.write(call.tool, a, etag, call.idem)
    except ErpConflict as c:
        events.emit(ctx, "downstream.failed", call.correlation, {"decision_id": call.decision_id, "kind": c.kind})
        if c.kind == "etag":
            call.check("erp.write", "fail", "If-Match failed")
            raise Stop(R.DENY_CONCURRENT_MODIFICATION, "ERP state changed during evaluation; retry", "R-GEN-04") from None
        call.check("erp.write", "fail", "ERP rejected duplicate")
        risk = a.get("amount_inr", 0)
        raise Stop(R.DENY_DUPLICATE_PAYMENT, "ERP rejected a duplicate", "R-PAY-01", risk) from None
    except ErpUnavailable as e:
        events.emit(ctx, "downstream.failed", call.correlation, {"decision_id": call.decision_id, "error": str(e)})
        call.check("erp.write", "error", str(e))
        raise Stop(R.DENY_DEPENDENCY_UNAVAILABLE, "ERP write failed") from None
    call.check("erp.write", "pass", "executed with If-Match + Idempotency-Key")
    events.emit(ctx, "downstream.executed", call.correlation, {"decision_id": call.decision_id, "tool": call.tool})
    return result


# ---------------------------------------------------------------------------------------------------------
# step 11-12

def _response(call: Call, code: R, message: str, rule_id=None, risk=0, formula=None, result=None,
              approval_id=None) -> dict:
    kind = kind_of(code)
    return {"decision_id": call.decision_id, "decision": kind, "reason_code": code.value, "rule_id": rule_id,
            "message": message, "inr_at_risk": int(risk), "formula": formula, "checks": call.checks,
            "result": result or {}, "approval_id": approval_id,
            "safe_alternatives": [] if kind == "ALLOW" else SAFE_ALTERNATIVES,
            "correlation_id": call.correlation, "idempotent_replay": False}


def finalize(call: Call, code: R, message: str, rule_id=None, risk=0, formula=None, result=None):
    ctx = call.ctx
    kind = kind_of(code)
    lease_id = call.lease["lease_id"] if call.lease else None
    suspended = False
    if lease_id and call.lease_ok:
        suspended, code, message = _account_lease(call, kind, code, message)
        kind = kind_of(code)
    approval_id = call.approval_id
    if kind == "HOLD":
        approval_id = _new_approval(call, f"{call.tool}: {message}", formula or message)
    resp = _response(call, code, message, rule_id, risk, formula, result, approval_id)
    status = http_status(code)
    with ctx.session() as s:
        s.add(Decision(decision_id=call.decision_id, lease_id=lease_id, task_id=call.body.get("task_id"),
                       correlation_id=call.correlation, call_id=call.body.get("call_id"),
                       step_id=call.body.get("step_id"), tool=call.tool, idempotency_key=call.idem,
                       request_hash=call.request_hash, args=call.args, decision=kind, reason_code=code.value,
                       rule_id=rule_id, inr_at_risk=int(risk), http_status=status, response=resp,
                       approval_id=approval_id))
        s.flush()
        if kind == "ALLOW" and call.is_write and call.idem and ctx.profile != "VULNERABLE":
            s.add(Idempotency(key=call.idem, request_hash=call.request_hash, decision_id=call.decision_id,
                              response=resp))
        try:
            s.commit()
        except IntegrityError:  # concurrent identical idempotency key; ERP's own key already de-duplicated
            s.rollback()
            s.add(Decision(decision_id=call.decision_id, lease_id=lease_id, task_id=call.body.get("task_id"),
                           correlation_id=call.correlation, call_id=call.body.get("call_id"), tool=call.tool,
                           decision=kind, reason_code=code.value, http_status=status, response=resp))
            s.commit()
    audit.append(ctx, call.decision_id, {
        "decision_id": call.decision_id, "ts": ctx.now().isoformat(), "lease_id": lease_id,
        "task_id": call.correlation, "call_id": call.body.get("call_id"), "tool": call.tool,
        "args_hash": sha256_hex(canonical(call.args)), "decision": kind, "reason_code": code.value,
        "rule_id": rule_id, "inr_at_risk": int(risk), "formula": formula, "policy_hash": ctx.policy.hash,
        "profile": ctx.profile})
    events.emit(ctx, "decision.made", call.correlation,
                {k: resp[k] for k in ("decision_id", "decision", "reason_code", "rule_id", "inr_at_risk",
                                      "formula", "message", "approval_id")} | {"tool": call.tool})
    if suspended:
        events.emit(ctx, "lease.suspended", call.correlation, {"lease_id": lease_id})
    return status, resp


def _account_lease(call: Call, kind: str, code: R, message: str):
    """calls_used++ always; denials++ on DENY; at the budget the lease is SUSPENDED (R-GEN-06)."""
    ctx, suspended = call.ctx, False
    with ctx.session() as s:
        vals = {}
        if call.count_call:
            vals["calls_used"] = Lease.calls_used + 1
        if kind == "DENY":
            vals["denials"] = Lease.denials + 1
        if vals:
            s.execute(update(Lease).where(Lease.lease_id == call.lease["lease_id"]).values(**vals))
        row = s.get(Lease, call.lease["lease_id"])
        if kind == "DENY" and row.denials >= ctx.policy.rules["denial_budget"] and row.status == "ACTIVE":
            row.status, suspended = "SUSPENDED", True
            code, message = R.DENY_DENIAL_BUDGET_EXHAUSTED, "Denial budget exhausted; lease suspended"
        s.commit()
    return suspended, code, message
