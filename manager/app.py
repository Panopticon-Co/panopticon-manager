"""FastAPI application factory. ``uvicorn manager.app:app`` boots this.

One uvicorn worker, sync handlers only, per ADR 003 — DetectionRun's engine
state (arriving in Phase 3) is in-process and must never be touched from more
than one worker or thread.
"""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI

from manager import config, db, migrations
from manager.routers import health


@asynccontextmanager
async def _lifespan(_: FastAPI):
    cfg = config.load()
    db.configure(cfg.db_path)
    migrations.migrate(db.connect())
    yield


app = FastAPI(title="Panopticon Manager", lifespan=_lifespan)
app.include_router(health.router)
