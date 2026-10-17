import pytest

from app.core.exceptions import NmapNotFoundError
from app.nmap import runner


def test_find_nmap_returns_full_path(monkeypatch):
    monkeypatch.setattr(runner.shutil, "which", lambda name: f"/usr/bin/{name}")

    assert runner.find_nmap() == "/usr/bin/nmap"


def test_find_nmap_raises_when_not_installed(monkeypatch):
    monkeypatch.setattr(runner.shutil, "which", lambda name: None)

    with pytest.raises(NmapNotFoundError, match="nmap is not installed"):
        runner.find_nmap()
