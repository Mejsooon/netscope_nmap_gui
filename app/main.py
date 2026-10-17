from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.staticfiles import StaticFiles

from app.api.errors import register_error_handlers
from app.api.routes import health, options, scans
from app.api.security import OriginCheckMiddleware
from app.services.scan_manager import ScanManager

LOCAL_HOSTS = ("127.0.0.1", "localhost")
FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"


def create_app(scan_manager: ScanManager | None = None, *, allowed_hosts: tuple[str, ...] = LOCAL_HOSTS) -> FastAPI:
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
    app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")
    app.add_middleware(OriginCheckMiddleware, allowed_hosts=allowed_hosts)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(allowed_hosts))
    return app


app = create_app()
