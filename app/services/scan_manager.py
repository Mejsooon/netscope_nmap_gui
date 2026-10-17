import logging
import threading
import uuid
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any

from app.core.exceptions import NetScopeError, ScanCancelledError
from app.nmap.command_builder import build_command
from app.nmap.runner import DEFAULT_TIMEOUT_SECONDS, NmapRunner, find_nmap
from app.nmap.xml_parser import parse_scan
from app.schemas.api import ScanJob
from app.schemas.scan import ScanRequest
from app.security.privileges import has_root_privileges
from app.storage.scan_store import ScanStore

logger = logging.getLogger(__name__)

DEFAULT_MAX_WORKERS = 2
INTERNAL_ERROR_MESSAGE = "Internal error while running the scan"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ScanManager:
    def __init__(
        self,
        *,
        store: ScanStore | None = None,
        runner_factory: Callable[..., NmapRunner] = NmapRunner,
        nmap_locator: Callable[[], str] = find_nmap,
        root_check: Callable[[], bool] = has_root_privileges,
        max_workers: int = DEFAULT_MAX_WORKERS,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self._store = store if store is not None else ScanStore()
        self._runner_factory = runner_factory
        self._nmap_locator = nmap_locator
        self._root_check = root_check
        self._timeout = timeout
        self._executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="nmap-scan")
        self._runners: dict[str, NmapRunner] = {}
        self._lock = threading.Lock()

    def is_root(self) -> bool:
        return self._root_check()

    def nmap_available(self) -> bool:
        try:
            self._nmap_locator()
        except NetScopeError:
            return False
        return True

    def submit(self, request: ScanRequest) -> ScanJob:
        command = build_command(request, is_root=self.is_root())
        self._nmap_locator()

        job = ScanJob(id=uuid.uuid4().hex, request=request, created_at=utc_now())
        runner = self._runner_factory(command, timeout=self._timeout)
        with self._lock:
            self._store.add(job)
            self._runners[job.id] = runner

        self._executor.submit(self._execute, job.id)
        return job

    def get(self, scan_id: str) -> ScanJob:
        return self._store.get(scan_id)

    def list(self) -> list[ScanJob]:
        return self._store.all()

    def shutdown(self) -> None:
        self._executor.shutdown(wait=True, cancel_futures=True)

    def _execute(self, scan_id: str) -> None:
        with self._lock:
            job = self._store.get(scan_id)
            if job.status != "queued":
                self._runners.pop(scan_id, None)
                return
            self._store.update(scan_id, status="running", started_at=utc_now())
            runner = self._runners[scan_id]

        try:
            result = parse_scan(runner.run())
        except ScanCancelledError:
            self._finish(scan_id, status="cancelled")
        except NetScopeError as error:
            self._finish(scan_id, status="failed", error=str(error))
        except Exception:
            logger.exception("Unexpected error in scan %s", scan_id)
            self._finish(scan_id, status="failed", error=INTERNAL_ERROR_MESSAGE)
        else:
            self._finish(scan_id, status="done", result=result)

    def _finish(self, scan_id: str, **changes: Any) -> None:
        with self._lock:
            self._runners.pop(scan_id, None)
            self._store.update(scan_id, finished_at=utc_now(), **changes)
