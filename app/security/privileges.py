import ctypes
import os


def has_root_privileges() -> bool:
    if hasattr(os, "geteuid"):
        return os.geteuid() == 0
    return _is_windows_admin()


def _is_windows_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False
