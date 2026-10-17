import pytest

from app.core.exceptions import InvalidTargetError, NmapExecutionError, NmapParseError
from app.schemas.scan import ScanRequest
from app.services import scan_service


class FakeRunner:
    instances: list["FakeRunner"] = []
    output = ""
    error: Exception | None = None

    def __init__(self, command, *, timeout):
        self.command = command
        self.timeout = timeout
        FakeRunner.instances.append(self)

    def run(self):
        if FakeRunner.error is not None:
            raise FakeRunner.error
        return FakeRunner.output


@pytest.fixture
def fake_runner(monkeypatch):
    FakeRunner.instances = []
    FakeRunner.output = ""
    FakeRunner.error = None
    monkeypatch.setattr(scan_service, "NmapRunner", FakeRunner)
    return FakeRunner


def test_run_scan_builds_runs_and_parses(fake_runner, load_fixture):
    fake_runner.output = load_fixture("scan_typical.xml")

    result = scan_service.run_scan(ScanRequest(target="192.168.1.1", ports="22,80,443"), timeout=30)

    runner = fake_runner.instances[0]
    assert runner.command == ["nmap", "-sT", "-T3", "-p", "22,80,443", "-oX", "-", "--", "192.168.1.1"]
    assert runner.timeout == 30
    assert [port.port for port in result.hosts[0].ports] == [22, 80, 443]


def test_invalid_request_never_starts_nmap(fake_runner):
    with pytest.raises(InvalidTargetError):
        scan_service.run_scan(ScanRequest(target="127.0.0.1; rm -rf ~"))

    assert fake_runner.instances == []


def test_runner_errors_are_passed_through(fake_runner):
    fake_runner.error = NmapExecutionError(1, "Failed to resolve")

    with pytest.raises(NmapExecutionError, match="Failed to resolve"):
        scan_service.run_scan(ScanRequest(target="192.168.1.1"))


def test_broken_output_raises_parse_error(fake_runner):
    fake_runner.output = "<nmaprun"

    with pytest.raises(NmapParseError):
        scan_service.run_scan(ScanRequest(target="192.168.1.1"))
