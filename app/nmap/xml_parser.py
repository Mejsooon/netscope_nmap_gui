from datetime import datetime, timezone
from xml.etree.ElementTree import Element, ParseError

from defusedxml import DefusedXmlException
from defusedxml.ElementTree import fromstring
from pydantic import ValidationError

from app.core.exceptions import NmapParseError
from app.schemas.scan import HostResult, ScanResult


def parse_scan(xml_text: str) -> ScanResult:
    root = _parse_root(xml_text)
    try:
        hosts = [_parse_host(host) for host in root.findall("host")]
        return _build_scan_result(root, hosts)
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


def _build_scan_result(root: Element, hosts: list[HostResult]) -> ScanResult:
    return ScanResult(
        nmap_version=root.get("version"),
        args=root.get("args"),
        started_at=_timestamp(root.get("start")),
        finished_at=_timestamp(_attr(root, "runstats/finished", "time")),
        elapsed_seconds=_attr(root, "runstats/finished", "elapsed"),
        hosts_up=_attr(root, "runstats/hosts", "up"),
        hosts_down=_attr(root, "runstats/hosts", "down"),
        hosts_total=_attr(root, "runstats/hosts", "total"),
        hosts=hosts,
    )


def _parse_host(host: Element) -> HostResult:
    addresses = {address.get("addrtype"): address for address in host.findall("address")}

    ip_element = addresses.get("ipv4")
    if ip_element is None:
        ip_element = addresses.get("ipv6")
    mac_element = addresses.get("mac")

    return HostResult(
        state=_attr(host, "status", "state"),
        ip=ip_element.get("addr") if ip_element is not None else None,
        mac=mac_element.get("addr") if mac_element is not None else None,
        mac_vendor=mac_element.get("vendor") if mac_element is not None else None,
    )


def _attr(element: Element, path: str, name: str) -> str | None:
    child = element.find(path)
    return child.get(name) if child is not None else None


def _timestamp(value: str | None) -> datetime | None:
    if value is None:
        return None
    return datetime.fromtimestamp(int(value), tz=timezone.utc)
