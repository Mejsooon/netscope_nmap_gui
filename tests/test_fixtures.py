import pytest
from defusedxml.ElementTree import fromstring


@pytest.mark.parametrize("name", ["scan_typical.xml", "scan_edge_cases.xml"])
def test_fixture_is_valid_nmap_xml(load_fixture, name):
    root = fromstring(load_fixture(name))

    assert root.tag == "nmaprun"
    assert root.find("runstats/finished").get("exit") == "success"


def test_typical_has_one_host_with_three_ports(load_fixture):
    root = fromstring(load_fixture("scan_typical.xml"))
    hosts = root.findall("host")

    assert len(hosts) == 1
    assert len(hosts[0].findall("ports/port")) == 3


def test_edge_cases_cover_expected_situations(load_fixture):
    root = fromstring(load_fixture("scan_edge_cases.xml"))
    hosts = root.findall("host")

    states = [host.find("status").get("state") for host in hosts]
    assert states == ["up", "down", "up"]

    first_host_ports = hosts[0].findall("ports/port")
    port_states = {p.get("portid"): p.find("state").get("state") for p in first_host_ports}
    assert port_states["80"] == "filtered"
    assert any(p.find("service") is None for p in first_host_ports)

    address_types = [a.get("addrtype") for a in hosts[0].findall("address")]
    assert address_types == ["ipv4", "mac"]

    assert hosts[1].find("ports") is None
    assert hosts[2].findall("ports/port") == []
    assert hosts[2].find("ports/extraports").get("state") == "filtered"


def test_edge_cases_runstats_match_hosts(load_fixture):
    root = fromstring(load_fixture("scan_edge_cases.xml"))
    stats = root.find("runstats/hosts")

    assert int(stats.get("total")) == len(root.findall("host"))
    assert int(stats.get("up")) == 2
    assert int(stats.get("down")) == 1
