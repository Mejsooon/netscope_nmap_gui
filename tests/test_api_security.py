import pytest


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
