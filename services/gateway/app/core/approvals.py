from datetime import UTC, datetime

from sqlalchemy import update

from app.core import events, pipeline
from app.core.tools import KIND
from app.db import Approval, Decision, Lease


def decide(ctx, approval_id: str, decision: str, approver: str, comment: str | None) -> dict:
    """APPROVE re-runs the stored call with HOLD reasons cleared (DENY rules still apply). Idempotent."""
    new_status = "APPROVED" if decision == "APPROVE" else "REJECTED"
    with ctx.session() as s:
        if s.get(Approval, approval_id) is None:
            raise LookupError(approval_id)
        claimed = s.execute(update(Approval).where(Approval.approval_id == approval_id, Approval.status == "PENDING")
                            .values(status=new_status, decided_by=approver, comment=comment,
                                    decided_at=datetime.now(UTC))).rowcount
        s.commit()
        appr = s.get(Approval, approval_id)
        orig = s.get(Decision, appr.decision_id)
        lease_row = s.get(Lease, appr.lease_id) if appr.lease_id else None
        lease = {c: getattr(lease_row, c) for c in ("lease_id", "task_id", "agent_id", "status", "scope", "exp",
                                                    "calls_used", "denials", "issued_by")} if lease_row else None
    if not claimed:  # already decided: return what happened the first time
        return _out(ctx, approval_id, None)
    events.emit(ctx, "approval.decided", orig.correlation_id,
                {"approval_id": approval_id, "status": new_status, "by": approver})
    result = None
    if new_status == "APPROVED" and KIND.get(orig.tool) == "write" and lease:
        _, result = pipeline.rerun_approved(ctx, orig, lease)
        with ctx.session() as s:
            s.execute(update(Approval).where(Approval.approval_id == approval_id)
                      .values(result_decision_id=result["decision_id"]))
            s.commit()
    return _out(ctx, approval_id, result)


def _out(ctx, approval_id: str, result: dict | None) -> dict:
    with ctx.session() as s:
        a = s.get(Approval, approval_id)
        if result is None and a.result_decision_id:
            result = s.get(Decision, a.result_decision_id).response
        return {"approval_id": approval_id, "status": a.status, "decided_by": a.decided_by, "result": result}
