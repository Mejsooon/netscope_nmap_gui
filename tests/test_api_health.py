from app.core.exceptions import NmapNotFoundError


def missing_nmap():
    raise NmapNotFoundError("nmap is not installed")


def test_health_ok_when_nmap_is_installed(api):
    response = api.client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "nmap_installed": True}


def test_health_degraded_when_nmap_is_missing(make_api):
    response = make_api(nmap_locator=missing_nmap).client.get("/health")

    assert response.status_code == 503
    assert response.json() == {"status": "degraded", "nmap_installed": False}


def test_app_shutdown_stops_the_scan_manager(make_api, monkeypatch):
    context = make_api()
    calls = []
    monkeypatch.setattr(context.manager, "shutdown", lambda: calls.append("shutdown"))

    context.client.__exit__(None, None, None)

    assert calls == ["shutdown"]
