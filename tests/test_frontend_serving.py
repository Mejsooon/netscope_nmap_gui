import pytest


def test_root_serves_the_frontend_page(api):
    response = api.client.get("/")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "<title>NetScope</title>" in response.text


def test_api_routes_take_priority_over_static_files(api):
    response = api.client.get("/scans")

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/json"


@pytest.mark.parametrize("path", [
    "/../app/main.py",
    "/%2e%2e/app/main.py",
    "/js/..%2f..%2fapp%2fmain.py",
    "/does-not-exist.js",
])
def test_files_outside_the_frontend_folder_are_not_served(api, path):
    response = api.client.get(path)

    assert response.status_code == 404
    assert "create_app" not in response.text
