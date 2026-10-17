from datetime import datetime, timezone
from typing import get_args

import pytest
from pydantic import ValidationError

from app.schemas.api import FINISHED_STATUSES, ScanJob, ScanStatus, ScanSummary
from app.schemas.scan import ScanRequest

NOW = datetime(2026, 10, 17, 12, 0, tzinfo=timezone.utc)
SCAN_ID = "0123456789abcdef0123456789abcdef"


def make_job(**overrides) -> ScanJob:
    data = {"id": SCAN_ID, "request": ScanRequest(target="192.168.1.1"), "created_at": NOW}
    data.update(overrides)
    return ScanJob(**data)


def test_new_job_is_queued_and_empty():
    job = make_job()

    assert job.status == "queued"
    assert job.result is None
    assert job.error is None
    assert job.is_finished is False


@pytest.mark.parametrize("status, finished", [
    ("queued", False), ("running", False), ("done", True), ("failed", True), ("cancelled", True),
])
def test_is_finished_follows_status(status, finished):
    assert make_job(status=status).is_finished is finished


def test_finished_statuses_are_a_subset_of_all_statuses():
    assert FINISHED_STATUSES < set(get_args(ScanStatus))


@pytest.mark.parametrize("scan_id", ["123", "../etc/passwd", SCAN_ID.upper(), SCAN_ID + "0"])
def test_job_id_must_be_32_lowercase_hex_characters(scan_id):
    with pytest.raises(ValidationError):
        make_job(id=scan_id)


def test_summary_contains_only_list_fields():
    job = make_job(status="done", finished_at=NOW)

    summary = ScanSummary.from_job(job)

    assert summary.model_dump() == {
        "id": SCAN_ID,
        "target": "192.168.1.1",
        "scan_type": "connect",
        "status": "done",
        "created_at": NOW,
        "finished_at": NOW,
    }
