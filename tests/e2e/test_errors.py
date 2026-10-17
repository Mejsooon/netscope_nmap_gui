import pytest
from playwright.sync_api import expect

pytestmark = pytest.mark.e2e


def submit(page, target, ports=None):
    page.locator("#target").fill(target)
    if ports is not None:
        page.locator("#ports").fill(ports)
    page.get_by_role("button", name="Uruchom skan").click()


@pytest.mark.parametrize("target, message", [
    ("127.0.0.1; rm -rf ~", "To nie jest adres IP, sieć ani hostname"),
    ("--script=vuln", "Cel nie może zaczynać się od „-”."),
    ("10.0.0.0/8", "Sieć jest za duża"),
])
def test_invalid_target_is_explained_next_to_the_field(page, live_app, target, message):
    page.browser_errors.allow("status of 400")
    page.goto(live_app.url)

    submit(page, target)

    expect(page.locator("#target-error")).to_contain_text(message)
    expect(page.locator("#target")).to_have_attribute("aria-invalid", "true")
    expect(page.locator("#target")).to_be_focused()
    expect(page.locator("#form-error")).to_be_hidden()
    assert live_app.factory.runners == []


@pytest.mark.parametrize("ports, message", [
    ("1-99999", "Porty muszą mieścić się w zakresie 1–65535."),
    ("22;80", "Nieprawidłowy format portów"),
    ("1000-1", "od mniejszej do większej"),
])
def test_invalid_ports_are_explained_next_to_the_field(page, live_app, ports, message):
    page.browser_errors.allow("status of 400")
    page.goto(live_app.url)

    submit(page, "192.168.1.1", ports=ports)

    expect(page.locator("#ports-error")).to_contain_text(message)
    expect(page.locator("#ports")).to_have_attribute("aria-invalid", "true")
    expect(page.locator("#target")).not_to_have_attribute("aria-invalid", "true")


def test_error_disappears_when_the_user_edits_the_field(page, live_app):
    page.browser_errors.allow("status of 400")
    page.goto(live_app.url)
    submit(page, "999.1.1.1")
    expect(page.locator("#target-error")).to_be_visible()

    page.locator("#target").press_sequentially("9")

    expect(page.locator("#target-error")).to_be_hidden()
    expect(page.locator("#target")).not_to_have_attribute("aria-invalid", "true")


def test_corrected_form_starts_the_scan(page, live_app):
    page.browser_errors.allow("status of 400")
    page.goto(live_app.url)
    submit(page, "999.1.1.1")
    expect(page.locator("#target-error")).to_be_visible()

    submit(page, "192.168.1.1")

    expect(page.locator("#result [data-status]")).to_have_text("zakończony")
    expect(page.locator("#target-error")).to_be_hidden()


def test_lost_connection_is_reported_for_the_whole_form(page, live_app):
    page.goto(live_app.url)
    page.route("**/scans", lambda route: route.abort() if route.request.method == "POST" else route.continue_())
    page.browser_errors.allow("ERR_FAILED")

    submit(page, "192.168.1.1")

    expect(page.locator("#form-error")).to_have_text("Brak połączenia z serwerem NetScope. Sprawdź, czy aplikacja działa.")
