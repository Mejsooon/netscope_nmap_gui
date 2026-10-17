from fastapi import APIRouter, Depends, Response, status

from app.api.dependencies import get_scan_manager
from app.schemas.api import ScanCreated
from app.schemas.scan import ScanRequest
from app.services.scan_manager import ScanManager

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post("", status_code=status.HTTP_202_ACCEPTED, response_model=ScanCreated)
def create_scan(
    request: ScanRequest,
    response: Response,
    manager: ScanManager = Depends(get_scan_manager),
) -> ScanCreated:
    job = manager.submit(request)
    response.headers["Location"] = f"/scans/{job.id}"
    return ScanCreated(id=job.id, status=job.status)
