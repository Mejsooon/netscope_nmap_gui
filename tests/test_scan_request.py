import pytest
from pydantic import ValidationError

from app.schemas.scan import ScanRequest


def test_scan_request_defaults():
    request = ScanRequest(target="192.168.1.1")

    assert request.scan_type == "connect"
    assert request.ports is None
    assert request.service_detection is False
    assert request.os_detection is False
    assert request.timing == 3


def test_scan_request_from_form_json():
    request = ScanRequest.model_validate(
        {
            "target": "192.168.1.0/24",
            "scan_type": "syn",
            "ports": "22,80,443",
            "service_detection": True,
            "timing": 4,
        }
    )

    assert request.scan_type == "syn"
    assert request.timing == 4


@pytest.mark.parametrize(
    "field, value",
    [
        ("target", ""),
        ("target", "a" * 254),
        ("scan_type", "-sS"),
        ("scan_type", "aggressive"),
        ("timing", 6),
        ("timing", -1),
        ("ports", ""),
    ],
)
def test_scan_request_rejects_invalid_values(field, value):
    data = {"target": "192.168.1.1", field: value}

    with pytest.raises(ValidationError):
        ScanRequest(**data)


def test_scan_request_rejects_unknown_fields():
    with pytest.raises(ValidationError):
        ScanRequest(target="192.168.1.1", extra_args="--script=vuln")
