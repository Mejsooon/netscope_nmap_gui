import pytest
from pydantic import ValidationError

from app.schemas.scan import ExtraPortsResult, HostResult, PortResult


def make_port(**overrides) -> PortResult:
    data = {"port": 22, "protocol": "tcp", "state": "open"}
    data.update(overrides)
    return PortResult(**data)


def test_port_result_minimal():
    port = make_port()

    assert port.port == 22
    assert port.service_name is None


def test_port_result_coerces_numeric_string():
    assert make_port(port="443").port == 443


@pytest.mark.parametrize("value", [0, 65536, -1])
def test_port_result_rejects_out_of_range_port(value):
    with pytest.raises(ValidationError):
        make_port(port=value)


@pytest.mark.parametrize("field, value", [("state", "weird"), ("protocol", "icmp")])
def test_port_result_rejects_unknown_literals(field, value):
    with pytest.raises(ValidationError):
        make_port(**{field: value})


def test_port_result_forbids_extra_fields():
    with pytest.raises(ValidationError):
        make_port(cpe="cpe:/a:openbsd:openssh")


def test_port_result_is_frozen():
    port = make_port()

    with pytest.raises(ValidationError):
        port.port = 80


def test_host_result_defaults_to_empty_collections():
    host = HostResult(state="down")

    assert host.ip is None
    assert host.hostnames == []
    assert host.ports == []
    assert host.extra_ports == []


@pytest.mark.parametrize("ip", ["192.168.1.1", "2001:db8::1"])
def test_host_result_accepts_ipv4_and_ipv6(ip):
    assert str(HostResult(state="up", ip=ip).ip) == ip


@pytest.mark.parametrize("ip", ["999.1.1.1", "router.lan", "192.168.1.0/24"])
def test_host_result_rejects_invalid_ip(ip):
    with pytest.raises(ValidationError):
        HostResult(state="up", ip=ip)


@pytest.mark.parametrize("mac", ["AA:BB:CC:11:22", "AA-BB-CC-11-22-33", "GG:BB:CC:11:22:33"])
def test_host_result_rejects_invalid_mac(mac):
    with pytest.raises(ValidationError):
        HostResult(state="up", mac=mac)


def test_host_result_nests_ports():
    host = HostResult(
        state="up",
        ports=[make_port()],
        extra_ports=[ExtraPortsResult(state="closed", count=997)],
    )

    assert host.ports[0].port == 22
    assert host.extra_ports[0].count == 997
