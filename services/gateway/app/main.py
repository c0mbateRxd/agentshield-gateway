import asyncio
import logging
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI

from app.api import core_routes, sandbox
from app.context import Ctx
from app.core import audit, events
from app.core.erp import ErpClient
from app.core.lease import LeaseKeys
from app.core.oracles import OracleClient
from app.core.policy import Policy
from app.db import make_session_factory
from app.settings import Settings

CHECKPOINT_EVERY_S = 60


def configure_logging():
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    structlog.configure(processors=[structlog.processors.add_log_level,
                                    structlog.processors.TimeStamper(fmt="iso"),
                                    structlog.processors.JSONRenderer()])


def create_app(settings: Settings | None = None, erp=None, oracles=None) -> FastAPI:
    settings = settings or Settings.from_env()
    policy = Policy(settings.policy_dir)
    ctx = Ctx(settings=settings, session=make_session_factory(settings.database_url),
              erp=erp or ErpClient(settings.erp_url, settings.erp_service_token),
              oracles=oracles or OracleClient(settings.oracles_url, timeout=policy.rules["oracle_timeout_s"]),
              policy=policy, keys=LeaseKeys(settings.lease_kid, settings.lease_signing_key, settings.lease_public_key))

    async def checkpoints():
        while True:
            await asyncio.sleep(CHECKPOINT_EVERY_S)
            h = await asyncio.to_thread(audit.head, ctx)
            await asyncio.to_thread(events.emit, ctx, "audit.checkpoint", None, {**h, "policy_hash": policy.hash})

    @asynccontextmanager
    async def lifespan(_):
        task = asyncio.create_task(checkpoints())
        yield
        task.cancel()

    app = FastAPI(title="AgentShield Agent Firewall gateway", lifespan=lifespan)
    app.state.ctx = ctx
    app.include_router(core_routes.router)
    if settings.sandbox:
        app.include_router(sandbox.router)
    return app


def app_factory() -> FastAPI:  # uvicorn --factory app.main:app_factory
    configure_logging()
    return create_app()
