import re

from app.core.exceptions import InvalidPortsError

MIN_PORT = 1
MAX_PORT = 65_535

PORT_SPEC_PATTERN = re.compile(r"[0-9]{1,5}(?:-[0-9]{1,5})?(?:,[0-9]{1,5}(?:-[0-9]{1,5})?)*")


def validate_ports(spec: str) -> str:
    if not PORT_SPEC_PATTERN.fullmatch(spec):
        raise InvalidPortsError(f"Invalid port specification: {spec!r} (use e.g. 22, 1-1000 or 22,80,443)")

    for item in spec.split(","):
        first_text, _, last_text = item.partition("-")
        first = int(first_text)
        last = int(last_text) if last_text else first

        if not MIN_PORT <= first <= MAX_PORT or not MIN_PORT <= last <= MAX_PORT:
            raise InvalidPortsError(f"Port out of range {MIN_PORT}-{MAX_PORT}: {item!r}")
        if first > last:
            raise InvalidPortsError(f"Port range must go from low to high: {item!r}")

    return spec
