import socket
import threading
import time
from dataclasses import dataclass, field

import pytest
import uvicorn

from app.main import create_app
from app.services.scan_manager import ScanManager
from tests.scan_fakes import FakeRunnerFactory

playwright_api = pytest.importorskip("playwright.sync_api")


class LiveServer:
    def __init__(self, app) -> None:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind(("127.0.0.1", 0))
        self.url = f"http://127.0.0.1:{self.socket.getsockname()[1]}"
        config = uvicorn.Config(app, log_level="warning", lifespan="on")
        self.server = uvicorn.Server(config)
        self.thread = threading.Thread(target=self.server.run, kwargs={"sockets": [self.socket]}, daemon=True)

    def start(self) -> None:
        self.thread.start()
        deadline = time.monotonic() + 10
        while not self.server.started:
            assert time.monotonic() < deadline, "server did not start"
            time.sleep(0.02)

    def stop(self) -> None:
        self.server.should_exit = True
        self.thread.join(timeout=10)


@dataclass
class LiveApp:
    url: str
    manager: ScanManager
    factory: FakeRunnerFactory


@pytest.fixture
def make_live_app():
    servers: list[LiveServer] = []

    def _make(factory: FakeRunnerFactory | None = None, **manager_options) -> LiveApp:
        factory = factory if factory is not None else FakeRunnerFactory()
        manager_options.setdefault("nmap_locator", lambda: "/usr/bin/nmap")
        manager_options.setdefault("root_check", lambda: False)
        manager = ScanManager(runner_factory=factory, **manager_options)
        server = LiveServer(create_app(manager))
        server.start()
        servers.append(server)
        return LiveApp(url=server.url, manager=manager, factory=factory)

    yield _make
    for server in servers:
        server.stop()


@pytest.fixture
def live_app(make_live_app) -> LiveApp:
    return make_live_app()


@pytest.fixture(scope="session")
def browser():
    with playwright_api.sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        yield browser
        browser.close()


@dataclass
class BrowserErrors:
    messages: list[str] = field(default_factory=list)
    allowed: list[str] = field(default_factory=list)

    def allow(self, fragment: str) -> None:
        self.allowed.append(fragment)

    def unexpected(self) -> list[str]:
        return [message for message in self.messages if not any(part in message for part in self.allowed)]


@pytest.fixture
def page(browser, make_live_app):
    # make_live_app is requested here only to fix the teardown order: pytest tears
    # fixtures down in reverse, so the page closes BEFORE its server stops.
    context = browser.new_context(locale="pl-PL")
    page = context.new_page()
    errors = BrowserErrors()
    page.on("console", lambda message: errors.messages.append(message.text) if message.type == "error" else None)
    page.on("pageerror", lambda error: errors.messages.append(str(error)))
    page.browser_errors = errors
    yield page
    page.unroute_all(behavior="ignoreErrors")
    context.close()
    assert errors.unexpected() == [], f"browser errors: {errors.unexpected()}"
