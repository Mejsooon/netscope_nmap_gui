import pytest
from playwright.sync_api import expect

from app.core.exceptions import NmapExecutionError
from tests.scan_fakes import FakeRunnerFactory

pytestmark = pytest.mark.e2e


def start_scan(page, target="192.168.1.1", ports=None):
    page.locator("#target").fill(target)
    if ports is not None:
        page.locator("#ports").fill(ports)
    page.get_by_role("button", name="Uruchom skan").click()


def test_scan_runs_and_shows_the_result_table(page, live_app):
    page.goto(live_app.url)

    start_scan(page, ports="22,80,443")

    result = page.locator("#result")
    expect(result.locator("[data-status]")).to_have_text("zakończony")
    expect(result.get_by_role("heading", name="192.168.1.1")).to_be_visible()
    expect(result).to_contain_text("1 host aktywny · 3 porty · 12,34 s")
    rows = result.locator("tbody tr")
    expect(rows).to_have_count(3)
    expect(rows.nth(0)).to_contain_text("22/tcp")
    expect(rows.nth(0)).to_contain_text("OpenSSH")
    expect(rows.nth(2)).to_contain_text("closed")
    expect(result.locator(".stat-value")).to_have_text(["2", "1", "0"])


def test_frontend_sends_the_form_values_to_the_api(page, live_app):
    page.goto(live_app.url)
    page.get_by_role("switch", name="Usługi i wersje").click()

    start_scan(page, target="  Router.LAN  ", ports="22")

    expect(page.locator("#result [data-status]")).to_have_text("zakończony")
    assert live_app.factory.runners[0].command == ["nmap", "-sT", "-sV", "-T3", "-p", "22", "-oX", "-", "--", "router.lan"]


def test_running_scan_shows_a_live_timer(page, make_live_app):
    app = make_live_app(FakeRunnerFactory(block=True))
    page.goto(app.url)

    start_scan(page)

    expect(page.locator("#result [data-status]")).to_have_text("w toku")
    expect(page.get_by_role("progressbar")).to_be_visible()
    expect(page.locator("#elapsed")).to_have_text("00:01", timeout=3000)

    app.factory.runners[0].release()
    expect(page.locator("#result [data-status]")).to_have_text("zakończony", timeout=5000)


def test_failed_scan_explains_the_error(page, make_live_app):
    app = make_live_app(FakeRunnerFactory(error=NmapExecutionError(1, 'Failed to resolve "nas.lan".')))
    page.goto(app.url)

    start_scan(page, target="nas.lan")

    result = page.locator("#result")
    expect(result.locator("[data-status]")).to_have_text("błąd")
    expect(result).to_contain_text("Nie udało się znaleźć hosta w DNS")
    expect(result.locator("code")).to_have_text('nmap exited with code 1: Failed to resolve "nas.lan".')


def test_reuse_fills_the_form_with_the_previous_request(page, live_app):
    page.goto(live_app.url)
    start_scan(page, target="10.0.0.5", ports="80,443")
    expect(page.locator("#result [data-status]")).to_have_text("zakończony")
    page.locator("#target").fill("")
    page.locator("#ports").fill("")

    page.get_by_role("button", name="Użyj ponownie").click()

    expect(page.locator("#target")).to_have_value("10.0.0.5")
    expect(page.locator("#ports")).to_have_value("80,443")
    expect(page.locator("#target")).to_be_focused()


def test_run_button_is_disabled_while_the_request_is_sent(page, live_app):
    page.goto(live_app.url)
    page.route("**/scans", lambda route: page.wait_for_timeout(500) or route.continue_())

    start_scan(page)

    expect(page.locator("#run")).to_be_disabled()
    expect(page.locator("#run-label")).to_have_text("Uruchamianie…")
    expect(page.locator("#run")).to_be_enabled(timeout=5000)


def test_cancel_stops_a_running_scan(page, make_live_app):
    app = make_live_app(FakeRunnerFactory(block=True))
    page.goto(app.url)
    start_scan(page)
    expect(page.locator("#result [data-status]")).to_have_text("w toku")

    page.get_by_role("button", name="Anuluj skan").click()

    expect(page.locator("#result [data-status]")).to_have_text("anulowany")
    expect(page.locator("#result")).to_contain_text("Skan został anulowany")
    assert app.factory.runners[0].cancelled.is_set()


def test_cancel_of_a_scan_that_just_finished_is_harmless(page, make_live_app):
    app = make_live_app(FakeRunnerFactory(block=True))
    page.goto(app.url)
    start_scan(page)
    expect(page.get_by_role("button", name="Anuluj skan")).to_be_visible()
    page.route("**/scans/*", lambda route: route.continue_() if route.request.method != "DELETE"
               else (app.factory.runners[0].release(), page.wait_for_timeout(300), route.continue_()))
    page.browser_errors.allow("status of 409")

    page.get_by_role("button", name="Anuluj skan").click()

    expect(page.locator("#result [data-status]")).to_have_text("zakończony")
    expect(page.locator("#form-error")).to_be_hidden()
