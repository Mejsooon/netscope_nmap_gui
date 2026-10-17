from app.nmap.options_catalog import (
    OS_DETECTION,
    SCAN_TYPES,
    SERVICE_DETECTION,
    TIMING_TEMPLATES,
    XML_OUTPUT_ARGS,
    NmapOption,
)
from app.schemas.scan import ScanRequest
from app.security.port_validator import validate_ports
from app.security.target_validator import validate_target

NMAP_EXECUTABLE = "nmap"


def build_command(request: ScanRequest) -> list[str]:
    target = validate_target(request.target)
    options = _selected_options(request)

    command = [NMAP_EXECUTABLE, *(option.flag for option in options)]
    if request.ports is not None:
        command += ["-p", validate_ports(request.ports)]
    command += [*XML_OUTPUT_ARGS, target]
    return command


def _selected_options(request: ScanRequest) -> list[NmapOption]:
    options = [SCAN_TYPES[request.scan_type]]
    if request.service_detection:
        options.append(SERVICE_DETECTION)
    if request.os_detection:
        options.append(OS_DETECTION)
    options.append(TIMING_TEMPLATES[request.timing])
    return options
