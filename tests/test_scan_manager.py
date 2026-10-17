import pytest

from app.core.exceptions import (
    InsufficientPrivilegesError,
    InvalidTargetError,
    NmapExecutionError,
    NmapNotFoundError,
    ScanAlreadyFinishedError,
    ScanNotFoundError,
)
from app.schemas.scan import ScanRequest
from app.services.scan_manager import INTERNAL_ERROR_MESSAGE, ScanManager
from tests.scan_fakes import FakeRunnerFactory, wait_for_status


def raise_not_found():
    raise NmapNotFoundError("nmap is not installed")


@pytest.fixture
def make_manager():
    managers = []

    def _make(factory=None, **options):
        options.setdefault("nmap_locator", lambda: "/usr/bin/nmap")
        options.setdefault("root_check", lambda: False)
        manager = ScanManager(runner_factory=factory or FakeRunnerFactory(), **options)
        managers.append(manager)
        return manager

    yield _make
    for manager in managers:
        manager.shutdown()


def test_submit_returns_queued_job_immediately(make_manager):
    factory = FakeRunnerFactory(block=True)
    manager = make_manager(factory)

    job = manager.submit(ScanRequest(target="192.168.1.1"))

    assert job.status == "queued"
    assert len(job.id) == 32
    factory.runners[0].release()


def test_scan_runs_in_background_and_finishes(make_manager):
    factory = FakeRunnerFactory()
    manager = make_manager(factory, timeout=30)

    job = manager.submit(ScanRequest(target="192.168.1.1", ports="22,80,443"))
    finished = wait_for_status(manager, job.id, "done")

    assert factory.runners[0].command[-1] == "192.168.1.1"
    assert factory.runners[0].timeout == 30
    assert finished.started_at is not None
    assert finished.finished_at >= finished.started_at
    assert [port.port for port in finished.result.hosts[0].ports] == [22, 80, 443]


def test_running_status_is_visible_while_nmap_works(make_manager):
    factory = FakeRunnerFactory(block=True)
    manager = make_manager(factory)

    job = manager.submit(ScanRequest(target="192.168.1.1"))
    factory.runners[0].started.wait(timeout=5)

    assert manager.get(job.id).status == "running"
    factory.runners[0].release()
    wait_for_status(manager, job.id, "done")


def test_invalid_request_is_rejected_before_a_job_exists(make_manager):
    manager = make_manager()

    with pytest.raises(InvalidTargetError):
        manager.submit(ScanRequest(target="127.0.0.1; rm -rf ~"))

    assert manager.list() == []


def test_root_options_use_the_injected_root_check(make_manager):
    manager = make_manager(root_check=lambda: False)

    with pytest.raises(InsufficientPrivilegesError):
        manager.submit(ScanRequest(target="192.168.1.1", scan_type="syn"))


def test_missing_nmap_is_reported_at_submit(make_manager):
    manager = make_manager(nmap_locator=raise_not_found)

    with pytest.raises(NmapNotFoundError):
        manager.submit(ScanRequest(target="192.168.1.1"))

    assert manager.nmap_available() is False


def test_nmap_runtime_error_marks_job_as_failed(make_manager):
    factory = FakeRunnerFactory(error=NmapExecutionError(1, "Failed to resolve"))
    manager = make_manager(factory)

    job = manager.submit(ScanRequest(target="192.168.1.1"))
    failed = wait_for_status(manager, job.id, "failed")

    assert failed.error == "nmap exited with code 1: Failed to resolve"
    assert failed.result is None


def test_broken_xml_marks_job_as_failed(make_manager):
    manager = make_manager(FakeRunnerFactory(output="<nmaprun"))

    job = manager.submit(ScanRequest(target="192.168.1.1"))

    assert wait_for_status(manager, job.id, "failed").error.startswith("Invalid XML")


def test_unexpected_error_is_hidden_from_the_user(make_manager, caplog):
    manager = make_manager(FakeRunnerFactory(error=RuntimeError("secret internal detail")))

    job = manager.submit(ScanRequest(target="192.168.1.1"))
    failed = wait_for_status(manager, job.id, "failed")

    assert failed.error == INTERNAL_ERROR_MESSAGE
    assert "secret internal detail" in caplog.text


def test_list_returns_newest_first(make_manager):
    manager = make_manager()

    first = manager.submit(ScanRequest(target="192.168.1.1"))
    second = manager.submit(ScanRequest(target="192.168.1.2"))

    assert [job.id for job in manager.list()] == [second.id, first.id]


def test_unknown_scan_id_raises_not_found(make_manager):
    with pytest.raises(ScanNotFoundError):
        make_manager().get("f" * 32)


def test_cancel_running_scan(make_manager):
    factory = FakeRunnerFactory(block=True)
    manager = make_manager(factory)
    job = manager.submit(ScanRequest(target="192.168.1.1"))
    factory.runners[0].started.wait(timeout=5)

    manager.cancel(job.id)

    cancelled = wait_for_status(manager, job.id, "cancelled")
    assert factory.runners[0].cancelled.is_set()
    assert cancelled.finished_at is not None
    assert cancelled.result is None


def test_cancel_queued_scan_never_starts_it(make_manager):
    factory = FakeRunnerFactory(block=True)
    manager = make_manager(factory, max_workers=1)
    busy = manager.submit(ScanRequest(target="192.168.1.1"))
    queued = manager.submit(ScanRequest(target="192.168.1.2"))
    factory.runners[0].started.wait(timeout=5)

    assert manager.cancel(queued.id).status == "cancelled"

    factory.runners[0].release()
    wait_for_status(manager, busy.id, "done")
    manager.shutdown()
    assert not factory.runners[1].started.is_set()
    assert manager.get(queued.id).status == "cancelled"


@pytest.mark.parametrize("final_status, options", [
    ("done", {}),
    ("failed", {"error": NmapExecutionError(1, "boom")}),
])
def test_finished_scan_cannot_be_cancelled(make_manager, final_status, options):
    manager = make_manager(FakeRunnerFactory(**options))
    job = manager.submit(ScanRequest(target="192.168.1.1"))
    wait_for_status(manager, job.id, final_status)

    with pytest.raises(ScanAlreadyFinishedError, match=f"already finished \\({final_status}\\)"):
        manager.cancel(job.id)


def test_cancelling_twice_is_rejected(make_manager):
    factory = FakeRunnerFactory(block=True)
    manager = make_manager(factory)
    job = manager.submit(ScanRequest(target="192.168.1.1"))
    factory.runners[0].started.wait(timeout=5)

    manager.cancel(job.id)
    wait_for_status(manager, job.id, "cancelled")

    with pytest.raises(ScanAlreadyFinishedError):
        manager.cancel(job.id)


def test_cancel_unknown_scan_raises_not_found(make_manager):
    with pytest.raises(ScanNotFoundError):
        make_manager().cancel("f" * 32)


def test_shutdown_cancels_running_scans(make_manager):
    factory = FakeRunnerFactory(block=True)
    manager = make_manager(factory)
    job = manager.submit(ScanRequest(target="192.168.1.1"))
    factory.runners[0].started.wait(timeout=5)

    manager.shutdown()

    assert manager.get(job.id).status == "cancelled"
