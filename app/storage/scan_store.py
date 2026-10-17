import threading
from typing import Any

from app.core.exceptions import ScanNotFoundError
from app.schemas.api import ScanJob


class ScanStore:
    def __init__(self) -> None:
        self._jobs: dict[str, ScanJob] = {}
        self._lock = threading.Lock()

    def add(self, job: ScanJob) -> None:
        with self._lock:
            if job.id in self._jobs:
                raise ValueError(f"Scan {job.id} already exists")
            self._jobs[job.id] = job

    def get(self, scan_id: str) -> ScanJob:
        with self._lock:
            return self._get(scan_id)

    def update(self, scan_id: str, **changes: Any) -> ScanJob:
        with self._lock:
            job = self._get(scan_id)
            updated = ScanJob.model_validate({**job.model_dump(), **changes})
            self._jobs[scan_id] = updated
            return updated

    def all(self) -> list[ScanJob]:
        with self._lock:
            return sorted(self._jobs.values(), key=lambda job: job.created_at, reverse=True)

    def _get(self, scan_id: str) -> ScanJob:
        try:
            return self._jobs[scan_id]
        except KeyError:
            raise ScanNotFoundError(f"Scan {scan_id} not found") from None
