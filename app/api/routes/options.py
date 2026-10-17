from fastapi import APIRouter, Depends

from app.api.dependencies import get_scan_manager
from app.nmap.options_catalog import OS_DETECTION, SCAN_TYPES, SERVICE_DETECTION, TIMING_TEMPLATES, NmapOption
from app.schemas.api import OptionInfo, OptionsResponse
from app.services.scan_manager import ScanManager

router = APIRouter(tags=["options"])


@router.get("/options", response_model=OptionsResponse)
def list_options(manager: ScanManager = Depends(get_scan_manager)) -> OptionsResponse:
    is_root = manager.is_root()

    def info(option: NmapOption) -> OptionInfo:
        return OptionInfo(
            flag=option.flag,
            description=option.description,
            requires_root=option.requires_root,
            available=is_root or not option.requires_root,
        )

    return OptionsResponse(
        is_root=is_root,
        scan_types={name: info(option) for name, option in SCAN_TYPES.items()},
        service_detection=info(SERVICE_DETECTION),
        os_detection=info(OS_DETECTION),
        timing={level: info(option) for level, option in TIMING_TEMPLATES.items()},
    )
