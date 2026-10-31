"""Auth, health, tasks, leases, tool-calls, decisions, approvals, events, audit."""
import uuid
from datetime import timedelta

import jwt
from fastapi import APIRouter, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import select
from sse_starlette.sse import EventSourceResponse

from app.core import audit, events, pipeline
from app.core.auth import bearer, check_login, claims_from_token, decode_token, issue_token, load_users, require_roles
from app.core.erp import ErpUnavailable
from app.core.oracles import OracleError
from app.core.reasons import ReasonCode as R
from app.db import Approval, Decision, Event, Lease, Task

router = APIRouter(prefix="/v1")
VIEW = ("business_operator", "business_approver", "defender", "attacker_sandbox", "admin")
LEASE_VIEW = ("business_operator", "business_approver", "defender", "admin")


def ctx_of(request: Request):
    return request.app.state.ctx


# ---- health + auth --------------------------------------------------------------------------------------

@router.get("/health")
def health():
    return {"status": "ok"}


@router.get("/health/all")
def health_all(request: Request, claims=require_roles(*VIEW)):
    ctx = ctx_of(request)

    def probe(fn):
        try:
            fn()
            return "ok"
        except Exception as e:
            return f"down: {type(e).__name__}"
    import httpx

    def agent():
        httpx.get(f"{ctx.settings.agent_url}/v1/model", timeout=2).raise_for_status()

    def db():
        with ctx.session() as s:
            s.execute(select(1))
    parts = {"db": probe(db), "erp": probe(ctx.erp.state_digest), "oracles": probe(ctx.oracles.health),
             "agent": probe(agent)}
    return {"status": "ok" if all(v == "ok" for v in parts.values()) else "degraded", **parts}


class Login(BaseModel):
    username: str
    password: str


@router.post("/auth/login")
def login(body: Login, request: Request):
    settings = ctx_of(request).settings
    user = check_login(settings, body.username, body.password)
    if not user:
        raise HTTPException(401, "invalid credentials")
    return {"token": issue_token(settings.jwt_secret, body.username, user["roles"]), "roles": user["roles"]}


# ---- tasks + leases -------------------------------------------------------------------------------------

class TaskIn(BaseModel):
    goal: str
    template: str = "AP_INBOX_V1"
    agent_id: str = "agent:ap-agent-01"


def _inbox_objects(ctx, allowed_suppliers, allowed_pos):
    """Objects referenced by the current inbox from KNOWN supplier domains only (ASSUMPTION: a supplier's
    POs are in scope when it has mail; see CCR-G1)."""
    try:
        inbox, _ = ctx.erp.read("inbox", unread_only=True)
    except ErpUnavailable:
        raise HTTPException(503, "ERP unavailable; cannot compute lease scope") from None
    suppliers, pos = set(), set()
    for m in inbox.get("messages", []):
        try:
            sup, _ = ctx.erp.read("supplier_by_domain", domain=m["from_domain"])
        except Exception:
            continue  # unknown domain: does not widen scope
        if sup["Supplier"] not in allowed_suppliers:
            continue
        suppliers.add(sup["Supplier"])
        try:
            orders, _ = ctx.erp.read("purchase_orders_for_supplier", supplier=sup["Supplier"])
            pos |= {p["PurchaseOrder"] for p in orders.get("purchase_orders", [])}
        except Exception:
            pass
    return sorted(suppliers), sorted(pos & set(allowed_pos))


@router.post("/tasks")
def create_task(body: TaskIn, request: Request, x_on_behalf_of: str | None = Header(None)):
    ctx = ctx_of(request)
    caller = claims_from_token(ctx.settings.jwt_secret, bearer(request))
    if not set(caller["roles"]) & {"agent", "business_operator"}:
        raise HTTPException(403, "caller may not create tasks")
    user = claims_from_token(ctx.settings.jwt_secret, x_on_behalf_of)
    if "business_operator" not in user["roles"]:
        raise HTTPException(403, "user is not a business_operator")
    tpl = ctx.policy.templates.get(body.template)
    if tpl is None:
        raise HTTPException(400, f"unknown template {body.template}")
    perms = load_users(ctx.settings).get(user["sub"], {})
    suppliers, pos = _inbox_objects(ctx, perms.get("allowed_suppliers", []), perms.get("allowed_purchase_orders", []))
    iat = int(ctx.now().timestamp())
    lease_id, task_id = str(uuid.uuid4()), str(uuid.uuid4())
    scope = {"tools": tpl["tools"], "suppliers": suppliers, "purchase_orders": pos,
             "max_payment_inr": min(tpl["max_payment_inr"], perms.get("max_payment_inr", 0)),
             "max_calls": tpl["max_calls"]}
    payload = {"v": 1, "lease_id": lease_id, "task_id": task_id, "agent_id": body.agent_id,
               "issued_by": user["sub"], "template": body.template, "iat": iat, "nbf": iat,
               "exp": iat + tpl["ttl_s"], "scope": scope}
    token = ctx.keys.sign(payload)
    with ctx.session() as s:
        s.add(Task(task_id=task_id, goal=body.goal, created_by=user["sub"]))
        s.add(Lease(lease_id=lease_id, task_id=task_id, agent_id=body.agent_id, issued_by=user["sub"],
                    template=body.template, scope=scope, iat=iat, exp=payload["exp"]))
        s.commit()
    events.emit(ctx, "task.created", task_id, {"task_id": task_id, "goal": body.goal, "issued_by": user["sub"]})
    events.emit(ctx, "lease.issued", task_id, {"lease_id": lease_id, "template": body.template, "scope": scope,
                                               "exp": payload["exp"]})
    return {"task_id": task_id, "lease_id": lease_id, "lease_token": token, "scope": scope, "exp": payload["exp"]}


def _lease_dict(row: Lease) -> dict:
    return {c: getattr(row, c) for c in ("lease_id", "task_id", "agent_id", "issued_by", "template", "scope",
                                         "iat", "exp", "status", "calls_used", "denials")}


@router.get("/leases/{lease_id}")
def get_lease(lease_id: str, request: Request, claims=require_roles(*LEASE_VIEW)):
    with ctx_of(request).session() as s:
        row = s.get(Lease, lease_id)
        if not row:
            raise HTTPException(404, "lease not found")
        return _lease_dict(row)


@router.post("/leases/{lease_id}/revoke")
def revoke_lease(lease_id: str, request: Request, claims=require_roles("business_operator", "admin")):
    ctx = ctx_of(request)
    with ctx.session() as s:
        row = s.get(Lease, lease_id)
        if not row:
            raise HTTPException(404, "lease not found")
        row.status = "REVOKED"
        s.commit()
        out = _lease_dict(row)
    events.emit(ctx, "lease.revoked", out["task_id"], {"lease_id": lease_id, "by": claims["sub"]})
    return out


# ---- tool calls -----------------------------------------------------------------------------------------

@router.post("/tool-calls")
async def tool_calls(request: Request):
    import asyncio
    try:
        body = await request.json()
    except ValueError:
        body = None
    status, resp = await asyncio.to_thread(pipeline.handle, ctx_of(request), bearer(request),
                                           request.headers.get("x-lease"), body)
    return JSONResponse(resp, status_code=status)


# ---- decisions + approvals ------------------------------------------------------------------------------

@router.get("/decisions")
def list_decisions(request: Request, correlation_id: str | None = None, limit: int = 100,
                   claims=require_roles(*LEASE_VIEW)):
    q = select(Decision).order_by(Decision.created_at.desc()).limit(min(limit, 500))
    if correlation_id:
        q = q.where(Decision.correlation_id == correlation_id)
    with ctx_of(request).session() as s:
        return [d.response for d in s.scalars(q)]


@router.get("/decisions/{decision_id}")
def get_decision(decision_id: str, request: Request, claims=require_roles(*LEASE_VIEW)):
    with ctx_of(request).session() as s:
        d = s.get(Decision, decision_id)
        if not d:
            raise HTTPException(404, "decision not found")
        return d.response


def _approval_dict(a: Approval) -> dict:
    return {c: (getattr(a, c).isoformat() if c.endswith("_at") and getattr(a, c) else getattr(a, c))
            for c in ("approval_id", "decision_id", "lease_id", "summary", "reason", "status",
                      "result_decision_id", "decided_by", "comment", "created_at", "decided_at")}


@router.get("/approvals")
def list_approvals(request: Request, status: str = "PENDING", claims=require_roles("business_approver", "admin", "defender")):
    with ctx_of(request).session() as s:
        return [_approval_dict(a) for a in s.scalars(
            select(Approval).where(Approval.status == status).order_by(Approval.created_at))]


class Decide(BaseModel):
    decision: str  # APPROVE | REJECT
    comment: str | None = None


@router.post("/approvals/{approval_id}/decide")
def decide_approval(approval_id: str, body: Decide, request: Request,
                    claims=require_roles("business_approver", "admin")):
    from app.core.approvals import decide
    if body.decision not in ("APPROVE", "REJECT"):
        raise HTTPException(400, "decision must be APPROVE or REJECT")
    try:
        return decide(ctx_of(request), approval_id, body.decision, claims["sub"], body.comment)
    except LookupError:
        raise HTTPException(404, "approval not found") from None


# ---- events + audit -------------------------------------------------------------------------------------

@router.post("/events/ingest")
def ingest(request: Request, body: dict, claims=require_roles("event_emitter")):
    for k in ("type", "payload"):
        if k not in body:
            raise HTTPException(400, f"missing {k}")
    seq = events.emit(ctx_of(request), body["type"], body.get("correlation_id"), body["payload"],
                      source=claims["sub"])
    return {"seq": seq}


@router.get("/events")
def get_events(request: Request, after: int = 0, limit: int = 100, correlation_id: str | None = None,
               claims=require_roles(*VIEW)):
    return events.list_events(ctx_of(request), after, limit, correlation_id)


@router.get("/events/stream")
async def stream(request: Request, token: str, after: int = 0, correlation_id: str | None = None,
                 last_event_id: str | None = Header(None)):
    ctx = ctx_of(request)
    claims = claims_from_token(ctx.settings.jwt_secret, token)  # EventSource cannot set headers
    if not set(claims["roles"]) & set(VIEW):
        raise HTTPException(403, "insufficient role")
    if last_event_id and last_event_id.isdigit():
        after = max(after, int(last_event_id))
    return EventSourceResponse(events.stream(ctx, after, correlation_id), ping=None)


@router.get("/audit/verify")
def audit_verify(request: Request, claims=require_roles("defender", "admin")):
    return audit.verify(ctx_of(request))
