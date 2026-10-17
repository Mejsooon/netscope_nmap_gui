from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from app.core.exceptions import ScanNotFoundError
from app.schemas.api import ScanJob
from app.schemas.scan import ScanRequest
from app.storage.scan_store import ScanStore

NOW = datetime(2026, 10, 17, 12, 0, tzinfo=timezone.utc)


def make_job(number: int = 0, **overrides) -> ScanJob:
    data = {
        "id": f"{number:032x}",
        "request": ScanRequest(target="192.168.1.1"),
        "created_at": NOW + timedelta(minutes=number),
    }
    data.update(overrides)
    return ScanJob(**data)


@pytest.fixture
def store():
    return ScanStore()


def test_added_job_can_be_read_back(store):
    job = make_job()
    store.add(job)

    assert store.get(job.id) == job


def test_duplicate_id_is_rejected(store):
    store.add(make_job())

    with pytest.raises(ValueError, match="already exists"):
        store.add(make_job())


def test_unknown_id_raises_not_found(store):
    with pytest.raises(ScanNotFoundError, match="not found"):
        store.get("f" * 32)


def test_update_returns_new_object_and_keeps_old_one_unchanged(store):
    job = make_job()
    store.add(job)

    updated = store.update(job.id, status="running", started_at=NOW)

    assert updated.status == "running"
    assert job.status == "queued"
    assert store.get(job.id) is updated


def test_update_is_validated(store):
    store.add(make_job())

    with pytest.raises(ValidationError):
        store.update(make_job().id, status="exploded")

    assert store.get(make_job().id).status == "queued"


def test_update_of_unknown_id_raises_not_found(store):
    with pytest.raises(ScanNotFoundError):
        store.update("f" * 32, status="running")


def test_all_returns_newest_first(store):
    for number in [1, 3, 2]:
        store.add(make_job(number))

    assert [job.id for job in store.all()] == [f"{n:032x}" for n in (3, 2, 1)]


def test_concurrent_adds_lose_nothing(store):
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda number: store.add(make_job(number)), range(500)))

    assert len(store.all()) == 500
