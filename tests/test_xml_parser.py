from datetime import datetime, timezone
from xml.etree.ElementTree import ParseError

import pytest

from app.core.exceptions import NmapParseError
from app.nmap.xml_parser import parse_scan


@pytest.fixture
def typical(load_fixture):
    return parse_scan(load_fixture("scan_typical.xml"))


@pytest.fixture
def edge(load_fixture):
    return parse_scan(load_fixture("scan_edge_cases.xml"))


def test_typical_scan_metadata(typical):
    assert typical.nmap_version == "7.95"
    assert typical.args == "nmap -sT -sV -p 22,80,443 -oX - 192.168.1.1"
    assert typical.started_at == datetime(2026, 10, 16, 18, 0, 0, tzinfo=timezone.utc)
    assert typical.finished_at == datetime(2026, 10, 16, 18, 0, 12, tzinfo=timezone.utc)
    assert typical.elapsed_seconds == 12.34


def test_typical_scan_host_counts(typical):
    assert (typical.hosts_up, typical.hosts_down, typical.hosts_total) == (1, 0, 1)


def test_edge_cases_host_counts(edge):
    assert (edge.hosts_up, edge.hosts_down, edge.hosts_total) == (2, 1, 3)


def test_typical_host_status_and_address(typical):
    host = typical.hosts[0]

    assert len(typical.hosts) == 1
    assert host.state == "up"
    assert str(host.ip) == "192.168.1.1"
    assert host.mac is None
    assert host.mac_vendor is None


def test_edge_cases_host_states_in_document_order(edge):
    assert [host.state for host in edge.hosts] == ["up", "down", "up"]
    assert [str(host.ip) for host in edge.hosts] == ["192.168.1.1", "192.168.1.2", "192.168.1.3"]


def test_edge_cases_ipv4_and_mac_are_separated(edge):
    first, _, third = edge.hosts

    assert first.mac == "AA:BB:CC:11:22:33"
    assert first.mac_vendor == "Example Networks"
    assert third.mac == "AA:BB:CC:44:55:66"
    assert third.mac_vendor is None


def test_ipv6_host_address(load_fixture):
    xml_text = load_fixture("scan_typical.xml").replace(
        'addr="192.168.1.1" addrtype="ipv4"', 'addr="2001:db8::1" addrtype="ipv6"'
    )

    assert str(parse_scan(xml_text).hosts[0].ip) == "2001:db8::1"


def test_hostnames_are_collected(typical, edge):
    assert typical.hosts[0].hostnames == ["router.lan"]
    assert edge.hosts[0].hostnames == ["router.lan"]


def test_missing_or_empty_hostnames_give_empty_list(edge):
    _, down_host, empty_hostnames_host = edge.hosts

    assert down_host.hostnames == []
    assert empty_hostnames_host.hostnames == []


def test_duplicate_hostnames_are_removed_keeping_order(load_fixture):
    xml_text = load_fixture("scan_typical.xml").replace(
        '<hostname name="router.lan" type="PTR"/>',
        '<hostname name="gateway" type="user"/>'
        '<hostname name="router.lan" type="PTR"/>'
        '<hostname name="gateway" type="PTR"/>',
    )

    assert parse_scan(xml_text).hosts[0].hostnames == ["gateway", "router.lan"]


def ports_by_number(host):
    return {port.port: port for port in host.ports}


def test_typical_ports_in_document_order(typical):
    ports = typical.hosts[0].ports

    assert [port.port for port in ports] == [22, 80, 443]
    assert [port.state for port in ports] == ["open", "open", "closed"]
    assert all(port.protocol == "tcp" for port in ports)


def test_typical_service_details_from_version_detection(typical):
    ssh = ports_by_number(typical.hosts[0])[22]

    assert ssh.service_name == "ssh"
    assert ssh.product == "OpenSSH"
    assert ssh.version == "9.6p1 Ubuntu 3ubuntu13.5"
    assert ssh.extra_info == "Ubuntu Linux; protocol 2.0"
    assert ssh.reason == "syn-ack"


def test_service_guessed_from_table_has_no_product(typical):
    https = ports_by_number(typical.hosts[0])[443]

    assert https.service_name == "https"
    assert https.product is None
    assert https.version is None


def test_filtered_port(edge):
    http = ports_by_number(edge.hosts[0])[80]

    assert http.state == "filtered"
    assert http.reason == "no-response"


def test_port_without_service_element(edge):
    unknown = ports_by_number(edge.hosts[0])[8080]

    assert unknown.state == "open"
    assert unknown.service_name is None
    assert unknown.product is None


def test_hosts_without_port_elements_have_no_ports(edge):
    _, down_host, filtered_host = edge.hosts

    assert down_host.ports == []
    assert filtered_host.ports == []


def test_extraports_summaries(edge):
    first, down_host, filtered_host = edge.hosts

    assert [(e.state, e.count) for e in first.extra_ports] == [("closed", 997)]
    assert down_host.extra_ports == []
    assert [(e.state, e.count) for e in filtered_host.extra_ports] == [("filtered", 1001)]


def test_extraports_are_not_listed_as_ports(edge):
    first = edge.hosts[0]

    assert len(first.ports) == 4
    assert len(first.ports) + first.extra_ports[0].count == 1001


INTERRUPTED_SCAN = """<nmaprun scanner="nmap" args="nmap -sT 10.0.0.0/30" start="1792173600" version="7.95">
<host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/></host>
<host><status state="down"/><address addr="10.0.0.2" addrtype="ipv4"/></host>
</nmaprun>"""


def test_interrupted_scan_without_runstats_counts_hosts():
    scan = parse_scan(INTERRUPTED_SCAN)

    assert (scan.hosts_up, scan.hosts_down, scan.hosts_total) == (1, 1, 2)
    assert scan.finished_at is None
    assert scan.elapsed_seconds is None


def test_runstats_take_priority_over_listed_hosts(load_fixture):
    xml_text = load_fixture("scan_edge_cases.xml").replace(
        '<hosts up="2" down="1" total="3"/>', '<hosts up="2" down="254" total="256"/>'
    )
    scan = parse_scan(xml_text)

    assert len(scan.hosts) == 3
    assert (scan.hosts_up, scan.hosts_down, scan.hosts_total) == (2, 254, 256)


@pytest.mark.parametrize("xml_text", ["", "not xml at all", "<nmaprun><host>"])
def test_invalid_xml_raises_parse_error(xml_text):
    with pytest.raises(NmapParseError, match="Invalid XML"):
        parse_scan(xml_text)


def test_invalid_xml_keeps_original_cause():
    with pytest.raises(NmapParseError) as excinfo:
        parse_scan("<nmaprun>")

    assert isinstance(excinfo.value.__cause__, ParseError)


def test_wrong_root_element_is_rejected():
    with pytest.raises(NmapParseError, match="Expected <nmaprun>"):
        parse_scan("<html><body>not nmap</body></html>")


def test_missing_required_attribute_is_rejected(load_fixture):
    xml_text = load_fixture("scan_typical.xml").replace('version="7.95"', "")

    with pytest.raises(NmapParseError, match="Unexpected nmap XML structure"):
        parse_scan(xml_text)
