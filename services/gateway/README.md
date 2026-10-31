# AgentShield · Agent Firewall gateway (`services/gateway`)

Policy enforcement + decision point between the agent and the ERP (FastAPI :8000). Owner: Chandan.
Spec: `MASTER_SPEC.md` (Prompt 1). Task: `../../02_Prompt_Chandan.md`.

```
cd services/gateway
python -m venv .venv && . .venv/Scripts/activate && pip install -e ".[dev]"
python -m pytest tests          # 85 tests, SQLite, fake ERP/oracles
python -m scripts.bench         # decision latency
python -m scripts.gen_keys      # Ed25519 dev keypair for .env
uvicorn app.main:app_factory --factory --port 8000
```

## Layout
- `app/core/pipeline.py` ordered tool-call pipeline (spec 10.1); only path to ALLOW is the end of `_execute`
- `app/core/rules.py` pure rule functions (spec 10.3); `policy/*.yaml` thresholds, templates, users (hashed at startup, hash in every decision)
- `app/core/{lease,auth,erp,oracles,events,audit,approvals,names,formatting}.py`
- `app/api/core_routes.py` all public endpoints; `app/api/sandbox.py` only mounted with `SANDBOX=1`

## Measured
Decision latency, in-process fakes + SQLite (no network, no model, no oracle timeout): read p95 ~15 ms,
rule-deny p95 ~18 ms (target < 400 ms). Re-measure against Postgres + real ERP in Day 5.

## Known gaps (honest list)
- Alembic migrations not written; tables come from `Base.metadata.create_all`. Postgres role `gw_svc` needs `search_path=gw`.
- Concurrency locks (per invoice/supplier/PO) and the audit-append lock are **per process**; run one worker, or add
  Postgres advisory locks before scaling out. ERP `If-Match` + `Idempotency-Key` remain the backstop.
- SSE uses a 250 ms table poll, not LISTEN/NOTIFY.
- Not yet verified against the real erp_sim / oracles: paths are assumptions (see `docs/contract-change-requests.md`).
- Overlay 13: templates SENSE/PLAN/LOGISTICS, tools `get_disruption_signals` etc., rule R-SIG-01 not built (no contract yet).
  R-FRT-03 (approval above Rs 2,00,000) is built.
