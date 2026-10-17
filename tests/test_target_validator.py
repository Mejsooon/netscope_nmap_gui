import pytest

from app.core.exceptions import InvalidTargetError
from app.security.target_validator import validate_target


@pytest.mark.parametrize(
    "target, expected",
    [
        ("192.168.1.1", "192.168.1.1"),
        ("10.0.0.0/8", "10.0.0.0/8"),
        ("2001:db8::1", "2001:db8::1"),
        ("2001:db8::/120", "2001:db8::/120"),
    ],
)
def test_valid_addresses_and_networks(target, expected):
    assert validate_target(target) == expected


def test_network_with_host_bits_is_normalized():
    assert validate_target("192.168.1.5/24") == "192.168.1.0/24"


def test_ipv6_address_is_written_in_canonical_form():
    assert validate_target("2001:0db8:0000:0000:0000:0000:0000:0001") == "2001:db8::1"


@pytest.mark.parametrize("target", ["-sS", "--script=vuln", "-iL /etc/passwd"])
def test_target_starting_with_dash_is_rejected(target):
    with pytest.raises(InvalidTargetError, match="must not start with '-'"):
        validate_target(target)


@pytest.mark.parametrize("target", ["999.1.1.1", "192.168.1.1/33", "192.168.1.1 ", ""])
def test_invalid_addresses_are_rejected(target):
    with pytest.raises(InvalidTargetError):
        validate_target(target)
