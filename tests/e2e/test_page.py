import pytest
from playwright.sync_api import expect

from app.core.exceptions import NmapNotFoundError

pytestmark = pytest.mark.e2e


def missing_nmap():
    raise NmapNotFoundError("nmap is not installed")


def test_page_loads_without_errors_or_csp_violations(page, live_app):
    page.goto(live_app.url)

    expect(page).to_have_title("NetScope")
    expect(page.get_by_role("heading", name="Nowy skan")).to_be_visible()
    expect(page.locator("#nmap-status")).to_have_text("nmap dostępny")
    expect(page.locator("#nmap-missing")).to_be_hidden()


def test_missing_nmap_shows_a_banner(page, make_live_app):
    page.browser_errors.allow("status of 503")
    page.goto(make_live_app(nmap_locator=missing_nmap).url)

    expect(page.locator("#nmap-status")).to_have_text("brak nmapa")
    expect(page.get_by_role("heading", name="Nie znaleziono nmapa")).to_be_visible()
    expect(page.get_by_role("link", name="Pobierz nmap")).to_have_attribute("href", "https://nmap.org/download")


def test_fonts_are_loaded_from_our_own_server(page, live_app):
    requests = []
    page.on("request", lambda request: requests.append(request.url))

    page.goto(live_app.url)
    page.wait_for_load_state("networkidle")

    assert any(url.endswith("/fonts/Geist-Variable.woff2") for url in requests)
    assert all(url.startswith(live_app.url) for url in requests)
