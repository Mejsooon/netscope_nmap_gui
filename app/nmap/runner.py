import shutil

from app.core.exceptions import NmapNotFoundError
from app.nmap.command_builder import NMAP_EXECUTABLE


def find_nmap() -> str:
    path = shutil.which(NMAP_EXECUTABLE)
    if path is None:
        raise NmapNotFoundError("nmap is not installed or not on PATH — install it from https://nmap.org/download")
    return path
