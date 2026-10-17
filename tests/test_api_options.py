from app.nmap.options_catalog import SCAN_TYPES, TIMING_TEMPLATES, NmapOption


def test_options_list_the_whole_catalog(api):
    data = api.client.get("/options").json()

    assert set(data["scan_types"]) == set(SCAN_TYPES)
    assert set(data["timing"]) == {str(level) for level in TIMING_TEMPLATES}
    assert data["scan_types"]["syn"] == {
        "flag": "-sS",
        "description": SCAN_TYPES["syn"].description,
        "requires_root": True,
        "available": False,
    }


def test_root_options_are_unavailable_without_root(api):
    data = api.client.get("/options").json()

    available = {name: option["available"] for name, option in data["scan_types"].items()}
    assert data["is_root"] is False
    assert available == {"connect": True, "syn": False, "udp": False, "ping": True}
    assert data["service_detection"]["available"] is True
    assert data["os_detection"]["available"] is False


def test_everything_is_available_with_root(make_api):
    data = make_api(root_check=lambda: True).client.get("/options").json()

    assert data["is_root"] is True
    assert all(option["available"] for option in data["scan_types"].values())
    assert data["os_detection"]["available"] is True


def test_new_catalog_option_appears_without_changing_the_api(api, monkeypatch):
    monkeypatch.setitem(SCAN_TYPES, "fin", NmapOption("-sF", "TCP FIN scan", requires_root=True))

    data = api.client.get("/options").json()

    assert data["scan_types"]["fin"]["flag"] == "-sF"
    assert data["scan_types"]["fin"]["available"] is False
