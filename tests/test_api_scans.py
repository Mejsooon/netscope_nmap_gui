import pytest

from app.core.exceptions import NmapNotFoundError
from tests.scan_fakes import wait_for_status


def missing_nmap():
    raise NmapNotFoundError("nmap is not installed or not on PATH")


# ═════════ POST /scans ═════════

def test_create_scan_returns_202_with_id_and_location(api):
    response = api.client.post("/scans", json={"target": "192.168.1.1", "ports": "22,80,443"})

    body = response.json()
    assert response.status_code == 202
    assert body["status"] == "queued"
    assert len(body["id"]) == 32
    assert response.headers["Location"] == f"/scans/{body['id']}"
    wait_for_status(api.manager, body["id"], "done")


def test_created_scan_uses_the_builder_command(api):
    body = api.client.post("/scans", json={"target": "Router.LAN", "service_detection": True}).json()
    wait_for_status(api.manager, body["id"], "done")

    assert api.factory.runners[0].command == ["nmap", "-sT", "-sV", "-T3", "-oX", "-", "--", "router.lan"]


@pytest.mark.parametrize("payload, message", [
    ({"target": "127.0.0.1; rm -rf ~"}, "Not a valid IP address"),
    ({"target": "--script=vuln"}, "must not start with '-'"),
    ({"target": "192.168.1.1", "ports": "1-99999"}, "out of range"),
    ({"target": "192.168.1.1", "scan_type": "syn"}, "require root"),
    ({"target": "0.0.0.0/0"}, "the limit is 65536"),
])
def test_invalid_scan_parameters_return_400_with_reason(api, payload, message):
    response = api.client.post("/scans", json=payload)

    assert response.status_code == 400
    assert message in response.json()["detail"]
    assert api.factory.runners == []


@pytest.mark.parametrize("payload", [
    {},
    {"target": ""},
    {"target": "192.168.1.1", "scan_type": "-sS"},
    {"target": "192.168.1.1", "timing": 9},
    {"target": "192.168.1.1", "extra_args": ["--script=vuln"]},
    {"target": "192.168.1.0/24", "scan_type": "ping", "ports": "22"},
])
def test_malformed_body_returns_422(api, payload):
    response = api.client.post("/scans", json=payload)

    assert response.status_code == 422
    assert api.factory.runners == []


def test_missing_nmap_returns_503(make_api):
    response = make_api(nmap_locator=missing_nmap).client.post("/scans", json={"target": "192.168.1.1"})

    assert response.status_code == 503
    assert "nmap is not installed" in response.json()["detail"]


@pytest.mark.parametrize("content_type", ["text/plain", "application/x-www-form-urlencoded", "multipart/form-data"])
def test_body_that_is_not_json_is_rejected(api, content_type):
    response = api.client.post(
        "/scans", content='{"target": "192.168.1.1"}', headers={"Content-Type": content_type}
    )

    assert response.status_code == 422
    assert api.factory.runners == []
