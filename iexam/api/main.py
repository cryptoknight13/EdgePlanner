"""FastAPI application factory.

Mounts route modules and installs cross-cutting handlers. Page-specific
routers (acg/start, acg/plan, ...) are added in subsequent slices.
"""
from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.core.errors import install_exception_handlers
from api.core.logging import setup_logging
from api.routes import health, logs
from api.routes.acg import metric1 as acg_metric1
from api.routes.acg import pddl as acg_pddl
from api.routes.acg import plan as acg_plan
from api.routes.acg import start as acg_start


def create_app() -> FastAPI:
    setup_logging()
    app = FastAPI(title="iEXAM API", version="0.1.0")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    install_exception_handlers(app)
    app.include_router(health.router)
    app.include_router(logs.router)
    app.include_router(acg_start.router)
    app.include_router(acg_pddl.router)
    app.include_router(acg_plan.router)
    app.include_router(acg_metric1.router)
    return app


app = create_app()
