import pytest
from playwright.sync_api import expect

from app.nmap.options_catalog import SCAN_TYPES, NmapOption

pytestmark = pytest.mark.e2e


def scan_type(page, name):
    return page.locator(f'[data-scan-type="{name}"]')


def test_form_is_built_from_the_options_endpoint(page, live_app):
    page.goto(live_app.url)

    expect(page.locator("[data-scan-type]")).to_have_count(len(SCAN_TYPES))
    expect(page.locator("[data-timing]")).to_have_count(6)
    expect(scan_type(page, "connect")).to_have_attribute("aria-pressed", "true")
    expect(page.locator("#root-status")).to_have_text("bez uprawnień root")


def test_root_options_are_locked_without_root(page, live_app):
    page.goto(live_app.url)

    for name in ("syn", "udp"):
        expect(scan_type(page, name)).to_be_disabled()
        expect(scan_type(page, name)).to_contain_text("Wymaga root")
    expect(page.locator('[data-option="os_detection"]')).to_be_disabled()
    expect(scan_type(page, "ping")).to_be_enabled()


def test_root_options_are_available_with_root(page, make_live_app):
    page.goto(make_live_app(root_check=lambda: True).url)

    expect(scan_type(page, "syn")).to_be_enabled()
    expect(page.locator("#root-status")).to_have_text("uprawnienia root")


def test_command_preview_follows_the_form(page, live_app):
    page.goto(live_app.url)
    command = page.locator("#command")

    expect(command).to_have_text("nmap -sT -T3 -oX - -- scanme.nmap.org")

    page.locator("#target").fill("192.168.1.1")
    page.get_by_role("switch", name="Usługi i wersje").click()
    page.get_by_role("button", name="Web 80,443").click()
    page.get_by_role("button", name="T4 Aggressive").click()

    expect(command).to_have_text("nmap -sT -sV -T4 -p 80,443 -oX - -- 192.168.1.1")
    expect(page.get_by_role("button", name="T4 Aggressive")).to_have_attribute("aria-pressed", "true")
    expect(page.locator("#timing-hint")).to_have_text("T4 · szybciej, zakłada stabilną sieć")


def test_ping_scan_disables_port_level_options(page, live_app):
    page.goto(live_app.url)
    page.get_by_role("switch", name="Usługi i wersje").click()
    page.locator("#ports").fill("22")

    scan_type(page, "ping").click()

    expect(page.locator("#ports")).to_be_disabled()
    expect(page.locator("#ports")).to_have_value("")
    expect(page.get_by_role("switch", name="Usługi i wersje")).to_be_disabled()
    expect(page.locator("#command")).to_have_text("nmap -sn -T3 -oX - -- scanme.nmap.org")


def test_switch_keeps_keyboard_focus_after_toggle(page, live_app):
    page.goto(live_app.url)
    switch = page.get_by_role("switch", name="Usługi i wersje")

    switch.focus()
    page.keyboard.press("Space")

    expect(switch).to_have_attribute("aria-checked", "true")
    expect(switch).to_be_focused()


def test_new_catalog_option_gets_a_button(page, live_app, monkeypatch):
    monkeypatch.setitem(SCAN_TYPES, "fin", NmapOption("-sF", "TCP FIN scan", requires_root=True))

    page.goto(live_app.url)

    expect(scan_type(page, "fin")).to_contain_text("-sF")
    expect(scan_type(page, "fin")).to_be_disabled()
