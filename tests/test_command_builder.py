import pytest

from app.core.exceptions import InvalidPortsError, InvalidTargetError
from app.nmap.command_builder import build_command
from app.schemas.scan import ScanRequest


def test_default_request():
    command = build_command(ScanRequest(target="192.168.1.1"))

    assert command == ["nmap", "-sT", "-T3", "-oX", "-", "192.168.1.1"]


def test_full_request():
    request = ScanRequest(
        target="192.168.1.0/24",
        scan_type="connect",
        ports="22,80,443",
        service_detection=True,
        timing=4,
    )

    assert build_command(request) == [
        "nmap", "-sT", "-sV", "-T4", "-p", "22,80,443", "-oX", "-", "192.168.1.0/24",
    ]


def test_ping_scan():
    command = build_command(ScanRequest(target="10.0.0.0/24", scan_type="ping"))

    assert command == ["nmap", "-sn", "-T3", "-oX", "-", "10.0.0.0/24"]


def test_target_is_normalized_by_validator():
    command = build_command(ScanRequest(target="Router.LAN"))

    assert command[-1] == "router.lan"


def test_every_argument_is_a_separate_list_element():
    command = build_command(ScanRequest(target="192.168.1.1", ports="1-1000", service_detection=True))

    assert all(isinstance(argument, str) for argument in command)
    assert all(" " not in argument for argument in command)


def test_invalid_target_stops_building():
    with pytest.raises(InvalidTargetError):
        build_command(ScanRequest(target="999.1.1.1"))


def test_invalid_ports_stop_building():
    with pytest.raises(InvalidPortsError):
        build_command(ScanRequest(target="192.168.1.1", ports="1-99999"))
