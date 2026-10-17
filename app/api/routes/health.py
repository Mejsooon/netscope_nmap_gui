from fastapi import APIRouter, Depends, Response, status

from app.api.dependencies import get_scan_manager
from app.schemas.api import HealthResponse
from app.services.scan_manager import ScanManager

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse)
def health(response: Response, manager: ScanManager = Depends(get_scan_manager)) -> HealthResponse:
    if manager.nmap_available():
        return HealthResponse(status="ok", nmap_installed=True)

    response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return HealthResponse(status="degraded", nmap_installed=False)
