import pytest

from tests.scan_fakes import FakeRunnerFactory


# ═════════ HOST HEADER (DNS rebinding) ═════════

@pytest.mark.parametrize("host", ["127.0.0.1:8000", "localhost:8000", "127.0.0.1", "localhost"])
def test_local_host_headers_are_accepted(api, host):
    assert api.client.get("/health", headers={"Host": host}).status_code == 200


@pytest.mark.parametrize("host", ["attacker.example:8000", "rebind.attacker.example", "192.168.1.10:8000", "127.0.0.1.attacker.example"])
def test_foreign_host_headers_are_rejected(api, host):
    response = api.client.get("/health", headers={"Host": host})

    assert response.status_code == 400
    assert response.text == "Invalid host header"


def test_rebinding_attack_cannot_start_a_scan(api):
    response = api.client.post(
        "/scans", json={"target": "192.168.1.1"}, headers={"Host": "rebind.attacker.example:8000"}
    )

    assert response.status_code == 400
    assert api.factory.runners == []


# ═════════ ORIGIN (cross-site requests) ═════════

SCAN = {"target": "192.168.1.1"}


@pytest.mark.parametrize("origin", ["http://127.0.0.1:8000", "http://localhost:8000", "http://localhost"])
def test_same_machine_origin_can_start_a_scan(api, origin):
    assert api.client.post("/scans", json=SCAN, headers={"Origin": origin}).status_code == 202


def test_request_without_origin_is_allowed(api):
    assert api.client.post("/scans", json=SCAN).status_code == 202


@pytest.mark.parametrize("origin", [
    "https://attacker.example",
    "http://127.0.0.1.attacker.example",
    "null",
    "file://",
    "http://192.168.1.10:8000",
])
def test_foreign_origin_cannot_start_a_scan(api, origin):
    response = api.client.post("/scans", json=SCAN, headers={"Origin": origin})

    assert response.status_code == 403
    assert response.json() == {"detail": "Cross-site request rejected"}
    assert api.factory.runners == []


def test_foreign_origin_cannot_cancel_a_scan(make_api):
    context = make_api(FakeRunnerFactory(block=True))
    scan_id = context.client.post("/scans", json=SCAN).json()["id"]

    response = context.client.delete(f"/scans/{scan_id}", headers={"Origin": "https://attacker.example"})

    assert response.status_code == 403
    assert context.manager.get(scan_id).status in {"queued", "running"}
    context.factory.runners[0].release()


def test_sec_fetch_site_cross_site_is_rejected_even_without_origin(api):
    response = api.client.post("/scans", json=SCAN, headers={"Sec-Fetch-Site": "cross-site"})

    assert response.status_code == 403


def test_reading_is_not_blocked_by_origin_check(api):
    assert api.client.get("/options", headers={"Origin": "https://attacker.example"}).status_code == 200


def test_no_cors_headers_are_sent(api):
    response = api.client.get("/options", headers={"Origin": "https://attacker.example"})

    assert "access-control-allow-origin" not in response.headers
