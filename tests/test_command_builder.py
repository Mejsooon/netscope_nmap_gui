import pytest

from app.core.exceptions import InsufficientPrivilegesError, InvalidPortsError, InvalidTargetError
from app.nmap import command_builder
from app.nmap.command_builder import build_command
from app.schemas.scan import ScanRequest


def test_default_request():
    command = build_command(ScanRequest(target="192.168.1.1"))

    assert command == ["nmap", "-sT", "-T3", "-oX", "-", "--", "192.168.1.1"]


def test_full_request():
    request = ScanRequest(
        target="192.168.1.0/24",
        scan_type="connect",
        ports="22,80,443",
        service_detection=True,
        timing=4,
    )

    assert build_command(request) == [
        "nmap", "-sT", "-sV", "-T4", "-p", "22,80,443", "-oX", "-", "--", "192.168.1.0/24",
    ]


def test_ping_scan():
    command = build_command(ScanRequest(target="10.0.0.0/24", scan_type="ping"))

    assert command == ["nmap", "-sn", "-T3", "-oX", "-", "--", "10.0.0.0/24"]


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


@pytest.mark.parametrize(
    "request_data, flag",
    [
        ({"scan_type": "syn"}, "-sS"),
        ({"scan_type": "udp"}, "-sU"),
        ({"os_detection": True}, "-O"),
    ],
)
def test_root_options_are_built_for_root(request_data, flag):
    command = build_command(ScanRequest(target="192.168.1.1", **request_data), is_root=True)

    assert flag in command


def test_syn_scan_without_root_suggests_connect_scan():
    with pytest.raises(InsufficientPrivilegesError, match=r"-sS require root.*\(-sT\) instead"):
        build_command(ScanRequest(target="192.168.1.1", scan_type="syn"), is_root=False)


def test_all_root_options_are_reported_together():
    request = ScanRequest(target="192.168.1.1", scan_type="udp", os_detection=True)

    with pytest.raises(InsufficientPrivilegesError, match="-sU, -O require root"):
        build_command(request, is_root=False)


def test_connect_scan_works_without_root():
    command = build_command(ScanRequest(target="192.168.1.1", service_detection=True), is_root=False)

    assert command[1:3] == ["-sT", "-sV"]


def test_privileges_are_detected_when_not_given(monkeypatch):
    monkeypatch.setattr("app.nmap.command_builder.has_root_privileges", lambda: False)

    with pytest.raises(InsufficientPrivilegesError):
        build_command(ScanRequest(target="192.168.1.1", scan_type="syn"))


def test_root_option_without_custom_hint_gets_default_hint(monkeypatch):
    monkeypatch.delitem(command_builder.ROOT_ALTERNATIVES, "-O")

    with pytest.raises(InsufficientPrivilegesError, match="run NetScope as root/administrator"):
        build_command(ScanRequest(target="192.168.1.1", os_detection=True), is_root=False)


def test_target_is_the_only_argument_after_end_of_options():
    command = build_command(ScanRequest(target="192.168.1.1", ports="22", service_detection=True))
    separator = command.index("--")

    assert command[separator + 1:] == ["192.168.1.1"]
    assert all(argument.startswith("-") or argument in {"nmap", "22"} for argument in command[:separator])
