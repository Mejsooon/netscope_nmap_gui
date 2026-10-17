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


class NmapRunError(NetScopeError):
    """Base class for problems while running the nmap process."""


class NmapNotFoundError(NmapRunError):
    """Raised when the nmap executable cannot be found on PATH."""


class NmapExecutionError(NmapRunError):
    """Raised when nmap exits with a non-zero return code."""

    def __init__(self, returncode: int, stderr: str) -> None:
        super().__init__(f"nmap exited with code {returncode}: {stderr}")
        self.returncode = returncode
        self.stderr = stderr


class ScanTimeoutError(NmapRunError):
    """Raised when a scan runs longer than its time limit."""


class ScanCancelledError(NmapRunError):
    """Raised when a running scan is cancelled by the user."""


class ScanJobError(NetScopeError):
    """Base class for errors about stored scan jobs."""


class ScanNotFoundError(ScanJobError):
    """Raised when no scan job has the requested id."""


class ScanAlreadyFinishedError(ScanJobError):
    """Raised when an action needs a running scan, but the scan has already finished."""
