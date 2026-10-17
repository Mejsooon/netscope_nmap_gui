import threading
import time
from pathlib import Path

TYPICAL_XML = (Path(__file__).parent / "fixtures" / "scan_typical.xml").read_text(encoding="utf-8")


class FakeRunner:
    def __init__(self, command, *, timeout, output=TYPICAL_XML, error=None, block=False):
        self.command = command
        self.timeout = timeout
        self.output = output
        self.error = error
        self.started = threading.Event()
        self.cancelled = threading.Event()
        self._release = threading.Event()
        if not block:
            self._release.set()

    def run(self):
        from app.core.exceptions import ScanCancelledError

        self.started.set()
        self._release.wait(timeout=10)
        if self.cancelled.is_set():
            raise ScanCancelledError("Scan was cancelled")
        if self.error is not None:
            raise self.error
        return self.output

    def release(self):
        self._release.set()

    def cancel(self):
        self.cancelled.set()
        self._release.set()


class FakeRunnerFactory:
    def __init__(self, **runner_options):
        self.runner_options = runner_options
        self.runners: list[FakeRunner] = []

    def __call__(self, command, *, timeout):
        runner = FakeRunner(command, timeout=timeout, **self.runner_options)
        self.runners.append(runner)
        return runner


def wait_for_status(manager, scan_id, *statuses, limit=5.0):
    deadline = time.monotonic() + limit
    while True:
        job = manager.get(scan_id)
        if job.status in statuses:
            return job
        assert time.monotonic() < deadline, f"scan stayed {job.status!r}, expected one of {statuses}"
        time.sleep(0.01)
