import shutil
import subprocess

from app.core.exceptions import NmapNotFoundError
from app.nmap.command_builder import NMAP_EXECUTABLE

DEFAULT_TIMEOUT_SECONDS = 600


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
        stdout, _stderr = self._process.communicate()
        return stdout
