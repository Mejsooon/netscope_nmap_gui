class NetScopeError(Exception):
    """Base class for all NetScope application errors."""


class NmapParseError(NetScopeError):
    """Raised when nmap XML output cannot be turned into a ScanResult."""
