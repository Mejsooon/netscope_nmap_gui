from dataclasses import dataclass


@dataclass(frozen=True)
class NmapOption:
    flag: str
    description: str
    requires_root: bool = False


SCAN_TYPES: dict[str, NmapOption] = {
    "connect": NmapOption("-sT", "TCP connect scan — full TCP handshake, works without root"),
    "syn": NmapOption("-sS", "TCP SYN scan — half-open, faster and quieter", requires_root=True),
    "udp": NmapOption("-sU", "UDP scan — slow, needs raw sockets", requires_root=True),
    "ping": NmapOption("-sn", "Host discovery only — no port scan"),
}

SERVICE_DETECTION = NmapOption("-sV", "Detect service names and versions on open ports")

OS_DETECTION = NmapOption("-O", "Detect the operating system", requires_root=True)

TIMING_TEMPLATES: dict[int, NmapOption] = {
    0: NmapOption("-T0", "Paranoid — one probe every 5 minutes"),
    1: NmapOption("-T1", "Sneaky — one probe every 15 seconds"),
    2: NmapOption("-T2", "Polite — slows down to use less bandwidth"),
    3: NmapOption("-T3", "Normal — nmap default"),
    4: NmapOption("-T4", "Aggressive — faster, assumes a reliable network"),
    5: NmapOption("-T5", "Insane — very fast, may miss ports or overload devices"),
}

XML_OUTPUT_ARGS: tuple[str, ...] = ("-oX", "-")
