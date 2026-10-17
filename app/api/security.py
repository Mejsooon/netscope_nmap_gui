from collections.abc import Iterable
from urllib.parse import urlsplit

from starlette.datastructures import Headers
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def is_allowed_origin(origin: str, allowed_hosts: Iterable[str]) -> bool:
    parts = urlsplit(origin)
    return parts.scheme in {"http", "https"} and parts.hostname in set(allowed_hosts)


class OriginCheckMiddleware:
    def __init__(self, app: ASGIApp, allowed_hosts: Iterable[str]) -> None:
        self.app = app
        self.allowed_hosts = frozenset(allowed_hosts)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and scope["method"] not in SAFE_METHODS:
            headers = Headers(scope=scope)
            origin = headers.get("origin")
            cross_site = headers.get("sec-fetch-site") == "cross-site"
            if cross_site or (origin is not None and not is_allowed_origin(origin, self.allowed_hosts)):
                response = JSONResponse({"detail": "Cross-site request rejected"}, status_code=403)
                await response(scope, receive, send)
                return

        await self.app(scope, receive, send)
