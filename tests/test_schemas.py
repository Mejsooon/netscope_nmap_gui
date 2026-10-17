import pytest
from pydantic import ValidationError

from app.schemas.scan import PortResult


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
