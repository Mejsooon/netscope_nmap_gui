import pytest

from app.core.exceptions import (
    InsufficientPrivilegesError,
    InvalidPortsError,
    InvalidScanRequestError,
    InvalidTargetError,
    NetScopeError,
    NmapParseError,
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
