"""Event hub. Envelope fields are an ASSUMPTION (spec section 11 not in shared text): CCR-G1."""
import asyncio
import json
from datetime import datetime

from sqlalchemy import select

from app.db import Event


def emit(ctx, type_: str, correlation_id: str | None, payload: dict, source: str = "gateway") -> int:
    with ctx.session() as s:
        e = Event(type=type_, source=source, correlation_id=correlation_id, payload=payload)
        s.add(e)
        s.commit()
        return e.seq


def to_dict(e: Event) -> dict:
    return {"seq": e.seq, "ts": e.ts.isoformat() if isinstance(e.ts, datetime) else e.ts, "type": e.type,
            "source": e.source, "correlation_id": e.correlation_id, "payload": e.payload}


def list_events(ctx, after: int = 0, limit: int = 100, correlation_id: str | None = None) -> list[dict]:
    q = select(Event).where(Event.seq > after).order_by(Event.seq).limit(min(limit, 1000))
    if correlation_id:
        q = q.where(Event.correlation_id == correlation_id)
    with ctx.session() as s:
        return [to_dict(e) for e in s.scalars(q)]


async def stream(ctx, after: int, correlation_id: str | None, poll_s: float = 0.25, heartbeat_s: float = 15):
    """SSE generator: short-poll the table (works on SQLite and Postgres), heartbeat every 15 s."""
    last_beat = asyncio.get_event_loop().time()
    while True:
        rows = await asyncio.to_thread(list_events, ctx, after, 200, correlation_id)
        for r in rows:
            after = r["seq"]
            yield {"id": str(r["seq"]), "event": r["type"], "data": json.dumps(r)}
        if rows:
            last_beat = asyncio.get_event_loop().time()
        elif asyncio.get_event_loop().time() - last_beat >= heartbeat_s:
            last_beat = asyncio.get_event_loop().time()
            yield {"event": "heartbeat", "data": "{}"}
        await asyncio.sleep(poll_s)
