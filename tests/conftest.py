from dataclasses import dataclass
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.services.scan_manager import ScanManager
from tests.scan_fakes import FakeRunnerFactory

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def load_fixture():
    def _load(name: str) -> str:
        return (FIXTURES_DIR / name).read_text(encoding="utf-8")

    return _load


@dataclass
class ApiContext:
    client: TestClient
    manager: ScanManager
    factory: FakeRunnerFactory


@pytest.fixture
def make_api():
    contexts: list[ApiContext] = []

    def _make(factory: FakeRunnerFactory | None = None, **manager_options) -> ApiContext:
        factory = factory if factory is not None else FakeRunnerFactory()
        manager_options.setdefault("nmap_locator", lambda: "/usr/bin/nmap")
        manager_options.setdefault("root_check", lambda: False)
        manager = ScanManager(runner_factory=factory, **manager_options)
        client = TestClient(create_app(manager), base_url="http://127.0.0.1:8000")
        client.__enter__()
        context = ApiContext(client=client, manager=manager, factory=factory)
        contexts.append(context)
        return context

    yield _make
    for context in contexts:
        context.client.__exit__(None, None, None)


@pytest.fixture
def api(make_api) -> ApiContext:
    return make_api()
