import shutil
import subprocess
import threading

from app.core.exceptions import (
    NmapExecutionError,
    NmapNotFoundError,
    ScanCancelledError,
    ScanTimeoutError,
)
from app.nmap.command_builder import NMAP_EXECUTABLE

DEFAULT_TIMEOUT_SECONDS = 600
MAX_STDERR_CHARS = 500
TERMINATE_GRACE_SECONDS = 5


def find_nmap() -> str:
    path = shutil.which(NMAP_EXECUTABLE)
    if path is None:
        raise NmapNotFoundError("nmap is not installed or not on PATH — install it from https://nmap.org/download")
    return path


class NmapRunner:
    def __init__(self, command: list[str], *, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> None:
        if not command or command[0] != NMAP_EXECUTABLE:
            raise ValueError("NmapRunner only runs commands built by build_command()")
        self._command = list(command)
        self._timeout = timeout
        self._process: subprocess.Popen[str] | None = None
        self._cancelled = threading.Event()
        self._lock = threading.Lock()

    def run(self) -> str:
        with self._lock:
            if self._process is not None:
                raise RuntimeError("NmapRunner can run only once")
            if self._cancelled.is_set():
                raise ScanCancelledError("Scan was cancelled before it started")

            arguments = [find_nmap(), *self._command[1:]]
            self._process = subprocess.Popen(
                arguments,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                shell=False,
            )

        try:
            stdout, stderr = self._process.communicate(timeout=self._timeout)
        except subprocess.TimeoutExpired as error:
            _terminate(self._process)
            self._process.communicate()
            raise ScanTimeoutError(f"Scan exceeded the time limit of {self._timeout} seconds") from error

        if self._cancelled.is_set():
            raise ScanCancelledError("Scan was cancelled")
        if self._process.returncode != 0:
            raise NmapExecutionError(self._process.returncode, _shorten(stderr))
        return stdout

    def cancel(self) -> None:
        self._cancelled.set()
        with self._lock:
            process = self._process
        if process is not None:
            _terminate(process)


def _terminate(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return

    process.terminate()
    try:
        process.wait(timeout=TERMINATE_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def _shorten(text: str) -> str:
    text = text.strip()
    if len(text) <= MAX_STDERR_CHARS:
        return text
    return text[:MAX_STDERR_CHARS] + "… (truncated)"
