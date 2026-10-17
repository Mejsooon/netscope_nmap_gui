import pytest
from playwright.sync_api import expect

from app.schemas.scan import ScanRequest
from tests.scan_fakes import wait_for_status

pytestmark = pytest.mark.e2e


def start_scan(page, target):
    page.locator("#target").fill(target)
    page.get_by_role("button", name="Uruchom skan").click()
    expect(page.locator("#result h2")).to_have_text(target)


def test_history_is_empty_at_start(page, live_app):
    page.goto(live_app.url)

    expect(page.locator("#history-empty")).to_be_visible()
    expect(page.locator(".history-item")).to_have_count(0)


def test_history_lists_scans_newest_first(page, live_app):
    page.goto(live_app.url)

    start_scan(page, "192.168.1.1")
    start_scan(page, "192.168.1.2")

    items = page.locator(".history-item")
    expect(items).to_have_count(2)
    expect(items.nth(0)).to_contain_text("192.168.1.2")
    expect(items.nth(0)).to_contain_text("-sT")
    expect(items.nth(0)).to_contain_text("teraz")
    expect(items.nth(0)).to_have_attribute("aria-current", "true")
    expect(page.locator("#history-empty")).to_be_hidden()


def test_clicking_a_history_item_shows_that_scan(page, live_app):
    page.goto(live_app.url)
    start_scan(page, "192.168.1.1")
    start_scan(page, "192.168.1.2")

    page.locator(".history-item", has_text="192.168.1.1").click()

    expect(page.locator("#result h2")).to_have_text("192.168.1.1")
    expect(page.locator(".history-item", has_text="192.168.1.1")).to_have_attribute("aria-current", "true")


def test_scans_from_before_the_page_was_opened_are_listed(page, live_app):
    job = live_app.manager.submit(ScanRequest(target="10.0.0.7", scan_type="ping"))
    wait_for_status(live_app.manager, job.id, "done")

    page.goto(live_app.url)

    item = page.locator(".history-item").first
    expect(item).to_contain_text("10.0.0.7")
    expect(item).to_contain_text("-sn")
    expect(item).to_contain_text("zakończony")
