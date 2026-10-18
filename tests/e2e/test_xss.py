import pytest
from playwright.sync_api import expect

from tests.scan_fakes import FakeRunnerFactory

pytestmark = pytest.mark.e2e

IMG_PAYLOAD = "<img src=x onerror=window.__xss=1>"
SCRIPT_PAYLOAD = "<script>window.__xss=2</script>"
SVG_PAYLOAD = '"><svg onload=window.__xss=3>'


def xml_escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


MALICIOUS_SCAN = f"""<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sT -sV -oX - -- 192.168.1.66" start="1792173600" version="7.95">
<host><status state="up"/><address addr="192.168.1.66" addrtype="ipv4"/>
<hostnames><hostname name="{xml_escape(SCRIPT_PAYLOAD)}" type="PTR"/></hostnames>
<ports>
<port protocol="tcp" portid="80"><state state="open"/>
<service name="http" product="{xml_escape(IMG_PAYLOAD)}" version="{xml_escape(SVG_PAYLOAD)}"/></port>
</ports></host>
<runstats><finished time="1792173601" elapsed="1.00" exit="success"/><hosts up="1" down="0" total="1"/></runstats>
</nmaprun>"""


def test_hostile_service_banners_are_shown_as_plain_text(page, make_live_app):
    app = make_live_app(FakeRunnerFactory(output=MALICIOUS_SCAN))
    page.goto(app.url)

    page.locator("#target").fill("192.168.1.66")
    page.get_by_role("button", name="Uruchom skan").click()

    result = page.locator("#result")
    expect(result.locator("[data-status]")).to_have_text("zakończony")
    expect(result.locator("td", has_text=IMG_PAYLOAD)).to_have_count(1)
    expect(result.locator("td", has_text=SVG_PAYLOAD)).to_have_count(1)
    expect(result.locator(".host-extra")).to_have_text(SCRIPT_PAYLOAD)
    expect(result.locator("img, script, svg[onload]")).to_have_count(0)
    page.wait_for_timeout(300)
    assert page.evaluate("window.__xss") is None


def test_csp_blocks_inline_code_even_if_html_were_injected(page, live_app):
    page.goto(live_app.url)
    page.browser_errors.allow("Content Security Policy")
    page.browser_errors.allow("status of 404")

    page.evaluate("""() => {
        const box = document.createElement('div');
        box.id = 'injected';
        document.body.append(box);
        box.innerHTML = '<img src=x onerror="window.__csp = 1">';
        const script = document.createElement('script');
        script.textContent = 'window.__csp = 2';
        document.body.append(script);
    }""")
    page.wait_for_timeout(300)

    assert page.evaluate("window.__csp") is None
    assert any("Content Security Policy" in message for message in page.browser_errors.messages)
