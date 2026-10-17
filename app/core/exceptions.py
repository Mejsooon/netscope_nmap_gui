class NetScopeError(Exception):
    """Base class for all NetScope application errors."""


class NmapParseError(NetScopeError):
    """Raised when nmap XML output cannot be turned into a ScanResult."""


class InvalidScanRequestError(NetScopeError):
    """Base class for errors in user-supplied scan parameters."""


class InvalidTargetError(InvalidScanRequestError):
    """Raised when the scan target is not a valid IP address, network or hostname."""


class InvalidPortsError(InvalidScanRequestError):
    """Raised when the port specification is malformed or out of range."""


class InsufficientPrivilegesError(InvalidScanRequestError):
    """Raised when a selected option needs root/administrator rights."""
