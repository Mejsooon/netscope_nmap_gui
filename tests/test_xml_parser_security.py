import pytest
from defusedxml import DefusedXmlException

from app.core.exceptions import NmapParseError
from app.nmap.xml_parser import parse_scan

BILLION_LAUGHS = """<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<nmaprun args="&lol4;"/>"""

EXTERNAL_ENTITY = """<?xml version="1.0"?>
<!DOCTYPE nmaprun [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<nmaprun args="&xxe;"/>"""

PLAIN_DOCTYPE = """<?xml version="1.0"?>
<!DOCTYPE nmaprun>
<nmaprun args="nmap" start="1792173600" version="7.95">
<runstats><hosts up="0" down="0" total="0"/></runstats>
</nmaprun>"""


@pytest.mark.parametrize("xml_text", [BILLION_LAUGHS, EXTERNAL_ENTITY], ids=["billion-laughs", "xxe"])
def test_entity_attacks_are_blocked(xml_text):
    with pytest.raises(NmapParseError, match="forbidden constructs") as excinfo:
        parse_scan(xml_text)

    assert isinstance(excinfo.value.__cause__, DefusedXmlException)


def test_plain_doctype_from_nmap_is_still_accepted():
    assert parse_scan(PLAIN_DOCTYPE).hosts_total == 0
