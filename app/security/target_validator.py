import ipaddress

from app.core.exceptions import InvalidTargetError


def validate_target(target: str) -> str:
    if target.startswith("-"):
        raise InvalidTargetError("Target must not start with '-'")

    network = _parse_network(target)
    if network is None:
        raise InvalidTargetError(f"Not a valid IP address or network: {target!r}")

    if "/" in target:
        return str(network)
    return str(network.network_address)


def _parse_network(target: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    try:
        return ipaddress.ip_network(target, strict=False)
    except ValueError:
        return None
