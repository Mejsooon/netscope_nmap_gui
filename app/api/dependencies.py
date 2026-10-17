from fastapi import Request

from app.services.scan_manager import ScanManager


def get_scan_manager(request: Request) -> ScanManager:
    return request.app.state.scan_manager
