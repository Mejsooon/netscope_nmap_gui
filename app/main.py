from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api.errors import register_error_handlers
from app.api.routes import health, options, scans
from app.services.scan_manager import ScanManager


def create_app(scan_manager: ScanManager | None = None) -> FastAPI:
    manager = scan_manager if scan_manager is not None else ScanManager()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        yield
        manager.shutdown()

    app = FastAPI(title="NetScope", version="0.1.0", lifespan=lifespan)
    app.state.scan_manager = manager
    app.include_router(health.router)
    app.include_router(options.router)
    app.include_router(scans.router)
    register_error_handlers(app)
    return app


app = create_app()
