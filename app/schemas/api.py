from datetime import datetime
from typing import Literal

from pydantic import Field

from app.schemas.scan import NetScopeModel, ScanRequest, ScanResult, ScanType

ScanStatus = Literal["queued", "running", "done", "failed", "cancelled"]
FINISHED_STATUSES: frozenset[str] = frozenset({"done", "failed", "cancelled"})

SCAN_ID_PATTERN = r"^[0-9a-f]{32}$"


class ScanJob(NetScopeModel):
    id: str = Field(pattern=SCAN_ID_PATTERN)
    request: ScanRequest
    status: ScanStatus = "queued"
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    result: ScanResult | None = None
    error: str | None = None

    @property
    def is_finished(self) -> bool:
        return self.status in FINISHED_STATUSES


class ScanSummary(NetScopeModel):
    id: str
    target: str
    scan_type: ScanType
    status: ScanStatus
    created_at: datetime
    finished_at: datetime | None = None

    @classmethod
    def from_job(cls, job: ScanJob) -> "ScanSummary":
        return cls(
            id=job.id,
            target=job.request.target,
            scan_type=job.request.scan_type,
            status=job.status,
            created_at=job.created_at,
            finished_at=job.finished_at,
        )


class ScanCreated(NetScopeModel):
    id: str
    status: ScanStatus


class OptionInfo(NetScopeModel):
    flag: str
    description: str
    requires_root: bool
    available: bool


class OptionsResponse(NetScopeModel):
    is_root: bool
    scan_types: dict[str, OptionInfo]
    service_detection: OptionInfo
    os_detection: OptionInfo
    timing: dict[int, OptionInfo]


class HealthResponse(NetScopeModel):
    status: Literal["ok", "degraded"]
    nmap_installed: bool
