"""Hash-chained audit log: entry_hash = sha256(prev_hash + canonical(payload)).
Appends are serialised by a process lock; multi-worker deployments need an advisory lock (README)."""
import threading

from sqlalchemy import select

from app.core.canonical import canonical, sha256_hex
from app.db import Audit

GENESIS = "0" * 64
_lock = threading.Lock()


def append(ctx, decision_id: str | None, payload: dict) -> Audit:
    body = canonical(payload).decode()
    with _lock, ctx.session() as s:
        prev = s.scalar(select(Audit.entry_hash).order_by(Audit.seq.desc()).limit(1)) or GENESIS
        row = Audit(decision_id=decision_id, prev_hash=prev, entry_hash=sha256_hex(prev + body),
                    payload_canonical=body)
        s.add(row)
        s.commit()
        return row


def verify(ctx) -> dict:
    prev, n = GENESIS, 0
    with ctx.session() as s:
        for row in s.scalars(select(Audit).order_by(Audit.seq)):
            n += 1
            if row.prev_hash != prev or row.entry_hash != sha256_hex(prev + row.payload_canonical):
                return {"ok": False, "entries": n, "first_bad_seq": row.seq}
            prev = row.entry_hash
    return {"ok": True, "entries": n, "first_bad_seq": None}


def head(ctx) -> dict:
    with ctx.session() as s:
        row = s.scalars(select(Audit).order_by(Audit.seq.desc()).limit(1)).first()
        return {"seq": row.seq if row else 0, "entry_hash": row.entry_hash if row else GENESIS}
