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


@pytest.mark.parametrize("path, content_type", [
    ("/css/style.css", "text/css"),
    ("/fonts/Geist-Variable.woff2", "font/woff2"),
    ("/fonts/GeistMono-Variable.woff2", "font/woff2"),
])
def test_static_assets_are_served_with_correct_types(api, path, content_type):
    response = api.client.get(path)

    assert response.status_code == 200
    assert response.headers["content-type"].startswith(content_type)


def test_page_has_no_inline_scripts_or_styles(api):
    html = api.client.get("/").text

    assert "<style" not in html
    assert 'style="' not in html
    assert " on" + "click=" not in html.lower()
    for line in html.splitlines():
        if "<script" in line:
            assert 'src="/js/' in line


def test_page_loads_nothing_from_other_origins(api):
    html = api.client.get("/").text
    css = api.client.get("/css/style.css").text

    for source in ('src="http', 'href="http'):
        assert source not in html.replace('href="https://nmap.org/download"', "")
    assert "url(http" not in css
    assert "@import" not in css


@pytest.mark.parametrize("module", ["app.js", "api.js", "dom.js", "form.js", "messages.js", "results.js"])
def test_javascript_modules_are_served(api, module):
    response = api.client.get(f"/js/{module}")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith(("text/javascript", "application/javascript"))


@pytest.mark.parametrize("module", ["app.js", "api.js", "dom.js", "form.js", "messages.js", "results.js"])
def test_javascript_never_writes_html_strings(api, module):
    source = api.client.get(f"/js/{module}").text

    for forbidden in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
        assert forbidden not in source
