"""FastAPI application factory. ``uvicorn manager.app:app`` boots this.

One uvicorn worker, sync handlers only, per ADR 003 — DetectionRun's engine
state is in-process and must never be touched from more than one worker or
thread. Detection runs on exactly one dedicated background thread, started here
in the lifespan and stopped cleanly on shutdown.
"""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI

from manager import config, db, migrations
from manager.detection.worker import DetectionWorker
from manager.routers import commands, enrollment, health, ingest


@asynccontextmanager
async def _lifespan(app: FastAPI):
    cfg = config.load()
    db.configure(cfg.db_path)
    migrations.migrate(db.connect())

    worker = DetectionWorker(
        db_path=cfg.db_path,
        alerts_path=cfg.alerts_path,
        rules_dir=cfg.rules_dir,
    )
    worker.start()
    app.state.detection_worker = worker
    try:
        yield
    finally:
        worker.stop()


app = FastAPI(title="Panopticon Manager", lifespan=_lifespan)
app.include_router(health.router)
app.include_router(ingest.router)
app.include_router(enrollment.router)
app.include_router(commands.router)
