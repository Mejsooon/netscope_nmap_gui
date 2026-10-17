import os

import pytest

from app.security import privileges


@pytest.mark.parametrize("euid, expected", [(0, True), (1000, False)])
def test_unix_privileges_follow_effective_user_id(monkeypatch, euid, expected):
    monkeypatch.setattr(os, "geteuid", lambda: euid, raising=False)

    assert privileges.has_root_privileges() is expected


def test_windows_path_is_used_without_geteuid(monkeypatch):
    monkeypatch.delattr(os, "geteuid", raising=False)
    monkeypatch.setattr(privileges, "_is_windows_admin", lambda: True)

    assert privileges.has_root_privileges() is True


def test_windows_check_fails_closed_when_api_is_missing(monkeypatch):
    monkeypatch.delattr(privileges.ctypes, "windll", raising=False)

    assert privileges._is_windows_admin() is False
