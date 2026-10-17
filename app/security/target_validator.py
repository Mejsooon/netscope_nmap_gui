import ipaddress
import re

from app.core.exceptions import InvalidTargetError

MAX_NETWORK_ADDRESSES = 65_536
MAX_HOSTNAME_LENGTH = 253

HOSTNAME_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")


def validate_target(target: str) -> str:
    if target.startswith("-"):
        raise InvalidTargetError("Target must not start with '-'")

    network = _parse_network(target)
    if network is None:
        if _is_valid_hostname(target):
            return target.lower()
        raise InvalidTargetError(f"Not a valid IP address, network or hostname: {target!r}")

    if network.num_addresses > MAX_NETWORK_ADDRESSES:
        raise InvalidTargetError(
            f"Network {network} has {network.num_addresses} addresses, "
            f"the limit is {MAX_NETWORK_ADDRESSES} (an IPv4 /16)"
        )

    if "/" in target:
        return str(network)
    return str(network.network_address)


def _parse_network(target: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    try:
        return ipaddress.ip_network(target, strict=False)
    except ValueError:
        return None


def _is_valid_hostname(target: str) -> bool:
    if len(target) > MAX_HOSTNAME_LENGTH:
        return False
    labels = target.split(".")
    if not all(HOSTNAME_LABEL.fullmatch(label) for label in labels):
        return False
    return not labels[-1].isdigit()
