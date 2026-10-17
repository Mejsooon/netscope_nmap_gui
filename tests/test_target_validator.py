import pytest

from app.core.exceptions import InvalidTargetError
from app.security.target_validator import validate_target


@pytest.mark.parametrize(
    "target, expected",
    [
        ("192.168.1.1", "192.168.1.1"),
        ("10.0.0.0/24", "10.0.0.0/24"),
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


@pytest.mark.parametrize("target", ["10.0.0.0/16", "2001:db8::/112"])
def test_network_at_size_limit_is_accepted(target):
    assert validate_target(target) == target


@pytest.mark.parametrize("target", ["10.0.0.0/15", "0.0.0.0/0", "2001:db8::/64"])
def test_too_large_network_is_rejected(target):
    with pytest.raises(InvalidTargetError, match="the limit is 65536"):
        validate_target(target)


@pytest.mark.parametrize(
    "target, expected",
    [
        ("scanme.nmap.org", "scanme.nmap.org"),
        ("router", "router"),
        ("Router.LAN", "router.lan"),
        ("my-server-01.example.com", "my-server-01.example.com"),
    ],
)
def test_valid_hostnames(target, expected):
    assert validate_target(target) == expected


@pytest.mark.parametrize(
    "target",
    [
        "bad_host.lan",
        "host-.lan",
        "host..lan",
        "example.com.",
        "a" * 64 + ".lan",
        ("a" * 60 + ".") * 5 + "lan",
        "1.2.3",
    ],
    ids=[
        "underscore",
        "label-ends-with-dash",
        "empty-label",
        "trailing-dot",
        "label-longer-than-63",
        "name-longer-than-253",
        "numeric-last-label",
    ],
)
def test_invalid_hostnames_are_rejected(target):
    with pytest.raises(InvalidTargetError, match="hostname"):
        validate_target(target)
