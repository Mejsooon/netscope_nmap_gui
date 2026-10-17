from datetime import datetime, timezone
from xml.etree.ElementTree import Element, ParseError

from defusedxml import DefusedXmlException
from defusedxml.ElementTree import fromstring
from pydantic import ValidationError

from app.core.exceptions import NmapParseError
from app.schemas.scan import ScanResult


def parse_scan(xml_text: str) -> ScanResult:
    root = _parse_root(xml_text)
    try:
        return _build_scan_result(root)
    except (ValidationError, ValueError) as error:
        raise NmapParseError(f"Unexpected nmap XML structure: {error}") from error


def _parse_root(xml_text: str) -> Element:
    try:
        root = fromstring(xml_text)
    except DefusedXmlException as error:
        raise NmapParseError("XML contains forbidden constructs (entities or external references)") from error
    except ParseError as error:
        raise NmapParseError(f"Invalid XML: {error}") from error

    if root.tag != "nmaprun":
        raise NmapParseError(f"Expected <nmaprun> root element, got <{root.tag}>")
    return root


def _build_scan_result(root: Element) -> ScanResult:
    return ScanResult(
        nmap_version=root.get("version"),
        args=root.get("args"),
        started_at=_timestamp(root.get("start")),
        finished_at=_timestamp(_attr(root, "runstats/finished", "time")),
        elapsed_seconds=_attr(root, "runstats/finished", "elapsed"),
        hosts_up=_attr(root, "runstats/hosts", "up"),
        hosts_down=_attr(root, "runstats/hosts", "down"),
        hosts_total=_attr(root, "runstats/hosts", "total"),
    )


def _attr(element: Element, path: str, name: str) -> str | None:
    child = element.find(path)
    return child.get(name) if child is not None else None


def _timestamp(value: str | None) -> datetime | None:
    if value is None:
        return None
    return datetime.fromtimestamp(int(value), tz=timezone.utc)
