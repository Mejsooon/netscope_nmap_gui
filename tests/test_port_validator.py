import pytest

from app.core.exceptions import InvalidPortsError
from app.security.port_validator import validate_ports


@pytest.mark.parametrize("spec", ["22", "1-1000", "22,80,443", "1-1024,3306,8000-8100", "1", "65535", "1-65535"])
def test_valid_port_specifications(spec):
    assert validate_ports(spec) == spec


@pytest.mark.parametrize(
    "spec",
    ["", "ssh", "22,", ",22", "22,,80", "22-", "-22", "22 80", "22;80", "1-2-3", "T:22", "123456"],
)
def test_malformed_specifications_are_rejected(spec):
    with pytest.raises(InvalidPortsError, match="Invalid port specification"):
        validate_ports(spec)


@pytest.mark.parametrize("spec", ["0", "65536", "1-99999", "22,0"])
def test_ports_out_of_range_are_rejected(spec):
    with pytest.raises(InvalidPortsError, match="out of range"):
        validate_ports(spec)


def test_reversed_range_is_rejected():
    with pytest.raises(InvalidPortsError, match="from low to high"):
        validate_ports("1000-1")
