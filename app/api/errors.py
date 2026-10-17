from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse

from app.core.exceptions import (
    InvalidScanRequestError,
    NetScopeError,
    NmapNotFoundError,
    ScanAlreadyFinishedError,
    ScanNotFoundError,
)

STATUS_CODES: dict[type[NetScopeError], int] = {
    InvalidScanRequestError: status.HTTP_400_BAD_REQUEST,
    ScanNotFoundError: status.HTTP_404_NOT_FOUND,
    ScanAlreadyFinishedError: status.HTTP_409_CONFLICT,
    NmapNotFoundError: status.HTTP_503_SERVICE_UNAVAILABLE,
}


def register_error_handlers(app: FastAPI) -> None:
    for error_class, status_code in STATUS_CODES.items():
        app.add_exception_handler(error_class, _make_handler(status_code))


def _make_handler(status_code: int):
    async def handler(request: Request, error: Exception) -> JSONResponse:
        return JSONResponse(status_code=status_code, content={"detail": str(error)})

    return handler
