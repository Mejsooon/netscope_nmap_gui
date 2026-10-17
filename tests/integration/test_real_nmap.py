import shutil

import pytest

from app.core.exceptions import NmapExecutionError, ScanTimeoutError
from app.nmap.command_builder import build_command
from app.nmap.runner import NmapRunner
from app.nmap.xml_parser import parse_scan
from app.schemas.scan import ScanRequest
from app.services.scan_service import run_scan

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(shutil.which("nmap") is None, reason="nmap is not installed"),
]


def test_connect_scan_of_localhost():
    result = run_scan(ScanRequest(target="127.0.0.1", ports="1-1024"), timeout=120)

    assert result.hosts_up == 1
    assert str(result.hosts[0].ip) == "127.0.0.1"


def test_end_of_options_separator_is_accepted_by_nmap():
    command = build_command(ScanRequest(target="127.0.0.1", ports="22"))
    assert "--" in command

    result = parse_scan(NmapRunner(command, timeout=60).run())

    assert " -- 127.0.0.1" in result.args
    assert result.hosts_total == 1


def test_scan_of_scanme_nmap_org():
    request = ScanRequest(target="scanme.nmap.org", ports="22,80", service_detection=True)

    result = run_scan(request, timeout=300)

    assert result.hosts_up == 1
    assert {port.port for port in result.hosts[0].ports} == {22, 80}


def test_unresolvable_hostname_gives_no_hosts_or_an_error():
    try:
        result = run_scan(ScanRequest(target="nonexistent-host.invalid", ports="22"), timeout=60)
    except NmapExecutionError:
        return

    assert result.hosts_total == 0


def test_very_slow_scan_hits_the_timeout():
    request = ScanRequest(target="127.0.0.1", ports="1-1000", timing=0)

    with pytest.raises(ScanTimeoutError):
        run_scan(request, timeout=3)
