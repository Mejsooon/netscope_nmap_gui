import signal
import subprocess
import sys
import time

import pytest

from app.core.exceptions import NmapExecutionError, NmapNotFoundError, ScanTimeoutError
from app.nmap import runner
from app.nmap.runner import NmapRunner


@pytest.fixture
def python_as_nmap(monkeypatch):
    monkeypatch.setattr(runner, "find_nmap", lambda: sys.executable)


def python_command(code: str) -> list[str]:
    return ["nmap", "-c", code]


def test_find_nmap_returns_full_path(monkeypatch):
    monkeypatch.setattr(runner.shutil, "which", lambda name: f"/usr/bin/{name}")

    assert runner.find_nmap() == "/usr/bin/nmap"


def test_find_nmap_raises_when_not_installed(monkeypatch):
    monkeypatch.setattr(runner.shutil, "which", lambda name: None)

    with pytest.raises(NmapNotFoundError, match="nmap is not installed"):
        runner.find_nmap()


@pytest.mark.parametrize("command", [[], ["/bin/sh", "-c", "id"], ["python", "-c", "1"]])
def test_runner_accepts_only_nmap_commands(command):
    with pytest.raises(ValueError, match="only runs commands built by build_command"):
        NmapRunner(command)


def test_run_returns_stdout(python_as_nmap):
    output = NmapRunner(python_command("print('<nmaprun/>')")).run()

    assert output.strip() == "<nmaprun/>"


def test_run_decodes_utf8_output(python_as_nmap):
    code = "import sys; sys.stdout.buffer.write('zażółć'.encode('utf-8'))"

    assert NmapRunner(python_command(code)).run() == "zażółć"


def test_invalid_utf8_bytes_are_replaced_not_fatal(python_as_nmap):
    code = "import sys; sys.stdout.buffer.write(b'ok\\xff')"

    assert NmapRunner(python_command(code)).run() == "ok�"


def test_runner_cannot_be_reused(python_as_nmap):
    nmap_runner = NmapRunner(python_command("pass"))
    nmap_runner.run()

    with pytest.raises(RuntimeError, match="only once"):
        nmap_runner.run()


def test_popen_is_called_without_shell_and_with_full_path(monkeypatch):
    calls = []

    class RecordingPopen:
        def __init__(self, arguments, **kwargs):
            calls.append((arguments, kwargs))
            self.returncode = 0

        def communicate(self, timeout=None):
            return "<nmaprun/>", ""

    monkeypatch.setattr(runner, "find_nmap", lambda: "/usr/bin/nmap")
    monkeypatch.setattr(runner.subprocess, "Popen", RecordingPopen)

    NmapRunner(["nmap", "-sT", "--", "192.168.1.1"]).run()

    arguments, kwargs = calls[0]
    assert arguments == ["/usr/bin/nmap", "-sT", "--", "192.168.1.1"]
    assert kwargs["shell"] is False
    assert kwargs["stdin"] is subprocess.DEVNULL


def test_non_zero_exit_raises_execution_error(python_as_nmap):
    code = "import sys; sys.stderr.write('Failed to resolve \"nosuchhost\".\\n'); sys.exit(1)"

    with pytest.raises(NmapExecutionError) as excinfo:
        NmapRunner(python_command(code)).run()

    assert excinfo.value.returncode == 1
    assert excinfo.value.stderr == 'Failed to resolve "nosuchhost".'


def test_long_stderr_is_truncated(python_as_nmap):
    code = "import sys; sys.stderr.write('x' * 10_000); sys.exit(2)"

    with pytest.raises(NmapExecutionError) as excinfo:
        NmapRunner(python_command(code)).run()

    assert len(excinfo.value.stderr) == runner.MAX_STDERR_CHARS + len("… (truncated)")
    assert excinfo.value.stderr.endswith("… (truncated)")


def test_warnings_on_stderr_do_not_fail_a_successful_scan(python_as_nmap):
    code = "import sys; sys.stderr.write('Warning: something minor'); print('<nmaprun/>')"

    assert NmapRunner(python_command(code)).run().strip() == "<nmaprun/>"


def test_scan_longer_than_timeout_is_stopped(python_as_nmap):
    nmap_runner = NmapRunner(python_command("import time; time.sleep(30)"), timeout=0.5)

    started = time.monotonic()
    with pytest.raises(ScanTimeoutError, match="time limit of 0.5 seconds"):
        nmap_runner.run()

    assert time.monotonic() - started < 10
    assert nmap_runner._process.poll() is not None


@pytest.mark.skipif(sys.platform == "win32", reason="SIGTERM cannot be ignored on Windows")
def test_process_ignoring_terminate_is_killed(python_as_nmap, monkeypatch):
    monkeypatch.setattr(runner, "TERMINATE_GRACE_SECONDS", 0.5)
    code = "import signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(30)"
    nmap_runner = NmapRunner(python_command(code), timeout=1.0)

    with pytest.raises(ScanTimeoutError):
        nmap_runner.run()

    assert nmap_runner._process.returncode == -signal.SIGKILL


def test_fast_scan_finishes_before_timeout(python_as_nmap):
    assert NmapRunner(python_command("print('done')"), timeout=10).run().strip() == "done"
