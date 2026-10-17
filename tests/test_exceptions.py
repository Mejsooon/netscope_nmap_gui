import pytest

from app.core.exceptions import (
    InsufficientPrivilegesError,
    InvalidPortsError,
    InvalidScanRequestError,
    InvalidTargetError,
    NetScopeError,
    NmapExecutionError,
    NmapNotFoundError,
    NmapParseError,
    NmapRunError,
    ScanCancelledError,
    ScanTimeoutError,
)


@pytest.mark.parametrize(
    "error_class",
    [InvalidTargetError, InvalidPortsError, InsufficientPrivilegesError],
)
def test_request_errors_share_one_base_class(error_class):
    assert issubclass(error_class, InvalidScanRequestError)
    assert issubclass(error_class, NetScopeError)


def test_parse_error_is_not_a_request_error():
    assert not issubclass(NmapParseError, InvalidScanRequestError)


@pytest.mark.parametrize(
    "error_class",
    [NmapNotFoundError, NmapExecutionError, ScanTimeoutError, ScanCancelledError],
)
def test_run_errors_share_one_base_class(error_class):
    assert issubclass(error_class, NmapRunError)
    assert not issubclass(error_class, InvalidScanRequestError)


def test_execution_error_keeps_return_code_and_stderr():
    error = NmapExecutionError(1, "Failed to resolve \"nosuchhost\".")

    assert error.returncode == 1
    assert error.stderr == "Failed to resolve \"nosuchhost\"."
    assert str(error) == "nmap exited with code 1: Failed to resolve \"nosuchhost\"."
