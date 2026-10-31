# PROMPT 2 · CHANDAN · AgentShield Gateway (the Agent Firewall)

> Paste into your AI coding assistant. First action: open and read `docs/MASTER_SPEC.md` in this repo (that is Prompt 1). It defines every shared contract: ports, auth, lease format, tool contracts, reason codes, rules, events, ERP contract. Follow it exactly. If something there is wrong, file a note in `docs/contract-change-requests.md` and keep building against the current contract. Do not edit other people's services. You own `services/gateway/**` and the gateway tests.

## Who you are
You are the lead engineer on the highest-workload module: the **Agent Firewall gateway**, the independent policy enforcement point (PEP) and decision point (PDP) between the agent and the ERP. This is the heart of AgentShield. Nothing the agent does reaches the ERP except through you.

## What to inspect first
1. `docs/MASTER_SPEC.md` Sections 6 to 12, 16, 18.
2. `contracts/python/agentshield_contracts/` for shared Pydantic models, the `ReasonCode` enum, event envelope, lease payload. If missing, create them from the spec and tell Pavan to move them into the contracts package.
3. `libs/common/` for auth, logging, canonical JSON, http client, event client.

## What you build (deliverables)

### A. Service skeleton (`services/gateway`, FastAPI :8000)
- `app/main.py`, routers under `app/api/`, settings from env, structlog JSON logs, `/v1/health` and `/v1/health/all` (checks DB, ERP `/sim/v1/state-digest`, oracles health, agent `/v1/model`, ollama via agent).
- Postgres schema `gw`, Alembic migrations, role `gw_svc`.
- Dockerfile, pyproject, pytest.

### B. Auth (`app/core/auth.py`, `app/api/auth.py`)
- `POST /v1/auth/login` → verify against demo users/passwords from env, issue HS256 JWT (claims per spec 7). Roles table in `policy/users.yaml`.
- Dependency `require_roles(...)` for every endpoint. Verify agent and service tokens.

### C. Capability leases (`app/core/lease.py`, `app/api/leases.py`, `app/api/tasks.py`)
- Ed25519 sign/verify, canonical JSON payload (spec 8.1). Keys from env; generate a dev keypair in `scripts` if absent.
- `POST /v1/tasks`: input `{goal}` + `X-On-Behalf-Of` user JWT; load template from `policy/templates.yaml`; compute scope = intersection(template, operator permissions, objects referenced by current inbox from known supplier domains); insert `gw.leases` row (ACTIVE); return `{task_id, lease_id, lease_token, scope, exp}`; emit `task.created` + `lease.issued`.
- `POST /v1/leases/{id}/revoke`, `GET /v1/leases/{id}`.
- Lease DB is authoritative for status/calls_used/denials; signature is integrity only.

### D. Tool-call pipeline (`app/api/toolcalls.py`, `app/core/pipeline.py`): the core
Implement `POST /v1/tool-calls` exactly per spec 10.1 to 10.3. Ordered pipeline, each step appends to `checks[]`:
1. authenticate agent (else DENY_AGENT_UNAUTHENTICATED, 401).
2. verify lease signature, kid, nbf/exp, DB status ACTIVE (else DENY_LEASE_*).
3. nonce: insert `gw.nonces(lease_id, call_id)` unique; duplicate → if same request hash and write tool, return stored idempotent response (`idempotent_replay:true`); else DENY_NONCE_REUSED (409).
4. timestamp window ±60 s (else DENY_STALE_REQUEST).
5. schema validate args against tool JSON schema (else DENY_SCHEMA_INVALID).
6. scope: tool in lease tools; all object IDs in args in lease scope; amount ≤ max_payment; calls_used < max_calls (else DENY_TOOL_NOT_IN_SCOPE / DENY_OBJECT_NOT_IN_SCOPE / DENY_AMOUNT_EXCEEDS_LEASE / DENY_CALL_BUDGET_EXHAUSTED).
7. fetch authoritative ERP state via ERP client (read with ETags).
8. deterministic rules for the tool (spec 10.3), using ERP data only. Build `inr_at_risk` and `formula`.
9. oracles where required (bank, freight), 2 s timeout, fail closed to HOLD.
10. decide ALLOW/HOLD/DENY. On HOLD create approval if needed. On ALLOW execute on ERP with `If-Match: <etag>` and `Idempotency-Key`; ETag changed → DENY_CONCURRENT_MODIFICATION (409); ERP duplicate 409 → DENY_DUPLICATE_PAYMENT.
11. persist decision, store idempotent response for write tools, increment calls_used; on DENY increment denials, at 3 → SUSPEND lease (emit `lease.suspended`), that call's reason becomes DENY_DENIAL_BUDGET_EXHAUSTED.
12. emit `toolcall.received`, `decision.made`, `downstream.executed/failed`.
Wrap the whole evaluation in try/except → DENY_POLICY_ERROR with a logged stack ID. Never let an exception produce an ALLOW.

### E. Rules engine (`app/core/rules/`, `policy/rules.yaml`)
- One pure function per rule_id (spec 10.3), table-driven, no I/O inside rule functions (pass them ERP data + args). Load tolerances/thresholds from `policy/rules.yaml`; hash the policy files at startup and include the hash in `audit.checkpoint` and in every decision's `checks`.
- Name normaliser + rapidfuzz scoring for R-BANK-01 (`app/core/names.py`): upper, strip PVT/PRIVATE/LTD/LIMITED/&/punctuation/extra spaces; score = max(token_set_ratio vs legal, vs trade).
- Indian-format formula strings (`app/core/formatting.py`): `format_inr(980000) -> "₹9,80,000"`.

### F. Oracle client (`app/core/oracles.py`)
Call oracles service for penny-drop, GSTIN, AIS. Timeout 2 s, retries 0, fail closed.

### G. ERP client (`app/core/erp.py`)
Read entities with ETag capture; execute writes with If-Match + Idempotency-Key + service token + `X-Sim-Profile`.

### H. Events + SSE (`app/core/events.py`, `app/api/events.py`)
- `gw.events` table with monotonic `seq` (DB sequence). `POST /v1/events/ingest` (role event_emitter) assigns seq. `GET /v1/events?after=&limit=&correlation_id=`. `GET /v1/events/stream` SSE (token via query param), `Last-Event-ID` support, 15 s heartbeat, backed by Postgres LISTEN/NOTIFY or short poll.
- Emit all gateway event types from spec 11.

### I. Approvals (`app/api/approvals.py`)
List pending, decide. APPROVE on a HOLD re-runs the original stored call with an override that clears only HOLD reasons (never DENY), then executes. Emit `approval.requested/decided`.

### J. Audit chain (`app/core/audit.py`, `app/api/audit.py`)
`gw.audit(seq, ts, decision_id, prev_hash, entry_hash, payload_canonical)`; entry_hash = sha256(prev_hash + canonical(payload)). `GET /v1/audit/verify` recomputes → `{ok, entries, first_bad_seq}`. Periodic `audit.checkpoint` event.

### K. Admin/sandbox (`app/api/admin.py`, `app/api/sandbox.py`): only when `SANDBOX=1`
- `POST /v1/admin/profile` PROTECTED|VULNERABLE (VULNERABLE = bypass rules/oracles/nonce/idempotency, broad static scope, send `X-Sim-Profile: VULNERABLE`; red banner event). Default PROTECTED, enforced and tested.
- `POST /v1/admin/reset` (revoke leases, clear nonces/idempotency/approvals, call ERP reset, emit `system.reset`).
- `GET /v1/sandbox/captures` returns redacted copies of recent real write tool-call requests for the replay attack.

## Interfaces you must honor
- Inbound from agent: `POST /v1/tool-calls` per spec 10.1.
- Inbound from web: auth, decisions, approvals, events, leases, audit, health.
- Outbound to ERP: spec 12. Outbound to oracles: spec 14 oracle endpoints (Kirti defines exact paths; agree Day 1).
- Response envelope and reason codes: spec 10.

## Tests you must write (`services/gateway/tests`)
- Table-driven rule tests covering every reason code with crafted ERP fixtures.
- Lease sign/verify, tamper, expiry, suspension, revoke.
- Nonce reuse; stale timestamp; idempotency (same key same hash → replay; same key different hash → deny).
- Scope: tool/object/amount/budget violations.
- ETag race: concurrent bank change then payment → DENY_CONCURRENT_MODIFICATION.
- Oracle timeout → HOLD_ORACLE_UNAVAILABLE; oracle mismatch → DENY_BANK_NAME_MISMATCH with correct inr_at_risk.
- Concurrency: 20 parallel payments (distinct call_ids, same idempotency key and same invoice) → exactly 1 executed. Also distinct idempotency keys same invoice → 1 ALLOW, rest DENY_DUPLICATE_PAYMENT.
- Policy exception path → DENY_POLICY_ERROR (inject via test flag).
- Default profile is PROTECTED.
- Audit chain verify OK and detects a tampered row.

## Acceptance criteria (your module)
- Every reason code reachable and asserted.
- No code path yields ALLOW on error, timeout, or unknown object.
- Decisions carry correct inr_at_risk and exact formula strings (match plan doc Section 5 numbers: ₹9,80,000 allowed; ₹48,50,000 BEC denied; ₹2,70,000 and ₹8,00,000 in batch).
- Decision latency p95 < 400 ms excluding model and excluding deliberate oracle timeout (measure, record).
- SSE delivers decisions to a subscribed client within 2 s; catch-up by `after=seq` returns missed events in order.

## Day plan
- Day 1: skeleton, auth/login, lease crypto, tool-call endpoint returning a stub decision, events table + ingest + SSE.
- Day 2: scope, nonce, timestamp, idempotency, ERP client, real ALLOW for a read tool and for post/pay happy path.
- Day 3: all rules, oracle client, HOLD + approvals.
- Day 4: audit chain, denial budget, VULNERABLE profile, reset, sandbox captures.
- Day 5: concurrency/race/perf tests, failure behaviors, help wire 3-view integration.
- Day 6: fixes only. Day 7: freeze, support rehearsals.

## Guardrails
Fail closed. Never trust agent-supplied amounts or IDs for a decision; always read ERP. Keep rule functions pure and unit-tested. Never log secrets or full tokens (log `kid`, `lease_id`, `sub` only). Do not widen scope from message content outside known supplier domains. No feature after Day 6.
