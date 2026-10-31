"""Admin + sandbox endpoints. Only mounted when SANDBOX=1."""
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import delete, select, update

from app.api.core_routes import ctx_of
from app.core import events
from app.core.auth import require_roles
from app.core.erp import ErpUnavailable
from app.db import Approval, Decision, Idempotency, Lease, Nonce

router = APIRouter(prefix="/v1")


class Profile(BaseModel):
    profile: str  # PROTECTED | VULNERABLE


@router.post("/admin/profile")
def set_profile(body: Profile, request: Request, claims=require_roles("admin", "attacker_sandbox", "defender")):
    ctx = ctx_of(request)
    if body.profile not in ("PROTECTED", "VULNERABLE"):
        raise HTTPException(400, "profile must be PROTECTED or VULNERABLE")
    ctx.profile = body.profile
    ctx.erp.profile = body.profile
    events.emit(ctx, "profile.changed", None, {"profile": body.profile, "by": claims["sub"],
                                               "banner": "RED: VULNERABLE profile active, rules bypassed"
                                               if body.profile == "VULNERABLE" else None})
    return {"profile": ctx.profile}


@router.get("/admin/profile")
def get_profile(request: Request, claims=require_roles("admin", "attacker_sandbox", "defender")):
    return {"profile": ctx_of(request).profile}


@router.post("/admin/reset")
def reset(request: Request, claims=require_roles("admin", "business_operator")):
    ctx = ctx_of(request)
    with ctx.session() as s:
        s.execute(update(Lease).where(Lease.status.in_(("ACTIVE", "SUSPENDED"))).values(status="REVOKED"))
        for table in (Nonce, Idempotency, Approval):
            s.execute(delete(table))
        s.commit()
    try:
        ctx.erp.reset()
    except ErpUnavailable:
        raise HTTPException(503, "gateway state cleared but ERP reset failed") from None
    ctx.profile = "PROTECTED"
    ctx.erp.profile = "PROTECTED"
    events.emit(ctx, "system.reset", None, {"by": claims["sub"]})
    return {"reset": True, "profile": ctx.profile}


@router.get("/sandbox/captures")
def captures(request: Request, limit: int = 20, claims=require_roles("attacker_sandbox", "admin")):
    """Recent executed write calls, minus every credential, for the replay attack."""
    with ctx_of(request).session() as s:
        rows = s.scalars(select(Decision).where(Decision.decision == "ALLOW", Decision.idempotency_key.is_not(None))
                         .order_by(Decision.created_at.desc()).limit(min(limit, 100)))
        return [{"decision_id": d.decision_id, "lease_id": d.lease_id,
                 "request": {"call_id": d.call_id, "idempotency_key": d.idempotency_key, "task_id": d.task_id,
                             "step_id": d.step_id, "tool": d.tool, "args": d.args}} for d in rows]
