"""Gateway tables. On Postgres the `gw_svc` role has search_path=gw (deploy/postgres/init.sql), so no
schema is hard-coded here; SQLite (tests) ignores schemas."""
from datetime import UTC, datetime

from sqlalchemy import JSON, Float, ForeignKey, Integer, String, Text, create_engine, event
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker


def now() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


class Lease(Base):
    __tablename__ = "leases"
    lease_id: Mapped[str] = mapped_column(String, primary_key=True)
    task_id: Mapped[str] = mapped_column(String, index=True)
    agent_id: Mapped[str] = mapped_column(String)
    issued_by: Mapped[str] = mapped_column(String)
    template: Mapped[str] = mapped_column(String)
    scope: Mapped[dict] = mapped_column(JSON)
    iat: Mapped[int] = mapped_column(Integer)
    exp: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String, default="ACTIVE")  # ACTIVE|SUSPENDED|REVOKED|EXPIRED
    calls_used: Mapped[int] = mapped_column(Integer, default=0)
    denials: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(default=now)


class Task(Base):
    __tablename__ = "tasks"
    task_id: Mapped[str] = mapped_column(String, primary_key=True)
    goal: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String, default="RUNNING")
    created_by: Mapped[str] = mapped_column(String)
    created_at: Mapped[datetime] = mapped_column(default=now)


class Nonce(Base):
    __tablename__ = "nonces"
    lease_id: Mapped[str] = mapped_column(String, primary_key=True)
    call_id: Mapped[str] = mapped_column(String, primary_key=True)
    request_hash: Mapped[str] = mapped_column(String)
    created_at: Mapped[datetime] = mapped_column(default=now)


class Decision(Base):
    __tablename__ = "decisions"
    decision_id: Mapped[str] = mapped_column(String, primary_key=True)
    lease_id: Mapped[str | None] = mapped_column(String, index=True, nullable=True)
    task_id: Mapped[str | None] = mapped_column(String, nullable=True)
    correlation_id: Mapped[str | None] = mapped_column(String, index=True, nullable=True)
    call_id: Mapped[str | None] = mapped_column(String, nullable=True)
    step_id: Mapped[str | None] = mapped_column(String, nullable=True)
    tool: Mapped[str | None] = mapped_column(String, nullable=True)
    idempotency_key: Mapped[str | None] = mapped_column(String, nullable=True)
    request_hash: Mapped[str | None] = mapped_column(String, nullable=True)
    args: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    decision: Mapped[str] = mapped_column(String)
    reason_code: Mapped[str] = mapped_column(String)
    rule_id: Mapped[str | None] = mapped_column(String, nullable=True)
    inr_at_risk: Mapped[float] = mapped_column(Float, default=0)
    http_status: Mapped[int] = mapped_column(Integer)
    response: Mapped[dict] = mapped_column(JSON)
    approval_id: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(default=now, index=True)


class Idempotency(Base):
    __tablename__ = "idempotency"
    key: Mapped[str] = mapped_column(String, primary_key=True)
    request_hash: Mapped[str] = mapped_column(String)
    decision_id: Mapped[str] = mapped_column(String, ForeignKey("decisions.decision_id"))
    response: Mapped[dict] = mapped_column(JSON)


class Approval(Base):
    __tablename__ = "approvals"
    approval_id: Mapped[str] = mapped_column(String, primary_key=True)
    decision_id: Mapped[str] = mapped_column(String)
    lease_id: Mapped[str | None] = mapped_column(String, nullable=True)
    summary: Mapped[str] = mapped_column(Text)
    reason: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String, default="PENDING")  # PENDING|APPROVED|REJECTED
    result_decision_id: Mapped[str | None] = mapped_column(String, nullable=True)
    decided_by: Mapped[str | None] = mapped_column(String, nullable=True)
    comment: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(default=now)
    decided_at: Mapped[datetime | None] = mapped_column(nullable=True)


class Event(Base):
    __tablename__ = "events"
    seq: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(default=now)
    type: Mapped[str] = mapped_column(String, index=True)
    source: Mapped[str] = mapped_column(String)
    correlation_id: Mapped[str | None] = mapped_column(String, index=True, nullable=True)
    payload: Mapped[dict] = mapped_column(JSON)


class Audit(Base):
    __tablename__ = "audit"
    seq: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(default=now)
    decision_id: Mapped[str | None] = mapped_column(String, nullable=True)
    prev_hash: Mapped[str] = mapped_column(String)
    entry_hash: Mapped[str] = mapped_column(String)
    payload_canonical: Mapped[str] = mapped_column(Text)


def make_session_factory(url: str) -> sessionmaker:
    kwargs = {}
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False, "timeout": 30}
    engine = create_engine(url, pool_pre_ping=True, **kwargs)
    if url.startswith("sqlite"):
        @event.listens_for(engine, "connect")
        def _pragmas(conn, _):
            conn.execute("PRAGMA journal_mode=WAL")
    Base.metadata.create_all(engine)  # Alembic migration pending; see README
    return sessionmaker(engine, expire_on_commit=False)
