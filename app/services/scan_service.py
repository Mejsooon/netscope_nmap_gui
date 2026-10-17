from app.nmap.command_builder import build_command
from app.nmap.runner import DEFAULT_TIMEOUT_SECONDS, NmapRunner
from app.nmap.xml_parser import parse_scan
from app.schemas.scan import ScanRequest, ScanResult


def run_scan(request: ScanRequest, *, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> ScanResult:
    command = build_command(request)
    xml_text = NmapRunner(command, timeout=timeout).run()
    return parse_scan(xml_text)
