import pytest

from app.core.exceptions import NmapNotFoundError
from tests.scan_fakes import FakeRunnerFactory, wait_for_status


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


# ═════════ GET /scans, GET /scans/{id} ═════════

def create(api, **payload):
    payload.setdefault("target", "192.168.1.1")
    return api.client.post("/scans", json=payload).json()["id"]


def test_get_scan_returns_status_and_result(api):
    scan_id = create(api, ports="22,80,443")
    wait_for_status(api.manager, scan_id, "done")

    body = api.client.get(f"/scans/{scan_id}").json()

    assert body["status"] == "done"
    assert body["request"]["ports"] == "22,80,443"
    assert body["result"]["hosts"][0]["ip"] == "192.168.1.1"
    assert [port["port"] for port in body["result"]["hosts"][0]["ports"]] == [22, 80, 443]
    assert body["error"] is None


def test_get_running_scan_has_no_result_yet(make_api):
    context = make_api(FakeRunnerFactory(block=True))
    scan_id = create(context)
    context.factory.runners[0].started.wait(timeout=5)

    body = context.client.get(f"/scans/{scan_id}").json()

    assert body["status"] == "running"
    assert body["result"] is None
    context.factory.runners[0].release()


def test_unknown_scan_returns_404(api):
    response = api.client.get(f"/scans/{'f' * 32}")

    assert response.status_code == 404
    assert "not found" in response.json()["detail"]


@pytest.mark.parametrize("scan_id", ["123", "F" * 32, "g" * 32, "f" * 31 + ";"])
def test_malformed_scan_id_returns_422(api, scan_id):
    assert api.client.get(f"/scans/{scan_id}").status_code == 422


@pytest.mark.parametrize("path", ["/scans/..%2F..%2Fetc%2Fpasswd", "/scans/a%2Fb", "/scans/../../etc/passwd"])
def test_paths_with_slashes_do_not_match_the_route(api, path):
    response = api.client.get(path)

    assert response.status_code == 404
    assert response.json() == {"detail": "Not Found"}


def test_list_scans_returns_summaries_newest_first(api):
    first = create(api, target="192.168.1.1")
    second = create(api, target="192.168.1.2", scan_type="ping")
    wait_for_status(api.manager, first, "done")
    wait_for_status(api.manager, second, "done")

    body = api.client.get("/scans").json()

    assert [item["id"] for item in body] == [second, first]
    assert body[0]["target"] == "192.168.1.2"
    assert body[0]["scan_type"] == "ping"
    assert "result" not in body[0]


def test_list_is_empty_at_start(api):
    assert api.client.get("/scans").json() == []


# ═════════ DELETE /scans/{id} ═════════

def test_cancel_running_scan_returns_204(make_api):
    context = make_api(FakeRunnerFactory(block=True))
    scan_id = create(context)
    context.factory.runners[0].started.wait(timeout=5)

    response = context.client.delete(f"/scans/{scan_id}")

    assert response.status_code == 204
    assert response.content == b""
    assert wait_for_status(context.manager, scan_id, "cancelled").result is None
    assert context.client.get(f"/scans/{scan_id}").json()["status"] == "cancelled"


def test_cancel_finished_scan_returns_409(api):
    scan_id = create(api)
    wait_for_status(api.manager, scan_id, "done")

    response = api.client.delete(f"/scans/{scan_id}")

    assert response.status_code == 409
    assert "already finished (done)" in response.json()["detail"]


def test_cancel_unknown_scan_returns_404(api):
    assert api.client.delete(f"/scans/{'f' * 32}").status_code == 404


def test_cancel_with_malformed_id_returns_422(api):
    assert api.client.delete("/scans/not-a-scan-id").status_code == 422
