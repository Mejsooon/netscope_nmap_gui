import shutil
import subprocess

from app.core.exceptions import NmapExecutionError, NmapNotFoundError, ScanTimeoutError
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

    def run(self) -> str:
        if self._process is not None:
            raise RuntimeError("NmapRunner can run only once")

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
            self._stop_process()
            raise ScanTimeoutError(f"Scan exceeded the time limit of {self._timeout} seconds") from error

        if self._process.returncode != 0:
            raise NmapExecutionError(self._process.returncode, _shorten(stderr))
        return stdout

    def _stop_process(self) -> None:
        process = self._process
        if process is None or process.poll() is not None:
            return

        process.terminate()
        try:
            process.wait(timeout=TERMINATE_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        process.communicate()


def _shorten(text: str) -> str:
    text = text.strip()
    if len(text) <= MAX_STDERR_CHARS:
        return text
    return text[:MAX_STDERR_CHARS] + "… (truncated)"
