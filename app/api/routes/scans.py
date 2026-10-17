from typing import Annotated

from fastapi import APIRouter, Depends, Path, Response, status

from app.api.dependencies import get_scan_manager
from app.schemas.api import SCAN_ID_PATTERN, ScanCreated, ScanJob, ScanSummary
from app.schemas.scan import ScanRequest
from app.services.scan_manager import ScanManager

router = APIRouter(prefix="/scans", tags=["scans"])

ScanId = Annotated[str, Path(pattern=SCAN_ID_PATTERN)]


@router.post("", status_code=status.HTTP_202_ACCEPTED, response_model=ScanCreated)
def create_scan(
    request: ScanRequest,
    response: Response,
    manager: ScanManager = Depends(get_scan_manager),
) -> ScanCreated:
    job = manager.submit(request)
    response.headers["Location"] = f"/scans/{job.id}"
    return ScanCreated(id=job.id, status=job.status)


@router.get("", response_model=list[ScanSummary])
def list_scans(manager: ScanManager = Depends(get_scan_manager)) -> list[ScanSummary]:
    return [ScanSummary.from_job(job) for job in manager.list()]


@router.get("/{scan_id}", response_model=ScanJob)
def get_scan(scan_id: ScanId, manager: ScanManager = Depends(get_scan_manager)) -> ScanJob:
    return manager.get(scan_id)
