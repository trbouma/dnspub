import dns.message
import dns.rcode
import dns.rdatatype

from nostrdns import npub_to_hex_pubkey, parse_into_dns_records
from npubresolver import build_response


OVERRIDE_NAME = (
    "npub1h9taws9gujwja2weyxzhawfahwqljcm3cs7wjv5vv70dvtx637wsl8rhx0."
    "npub.openproof.org"
)


def query(name: str, record_type: str):
    request = dns.message.make_query(name, record_type)
    return dns.message.from_wire(build_response(request.to_wire()))


def test_zone_apex_returns_soa():
    response = query("npub.openproof.org", "SOA")

    assert response.rcode() == dns.rcode.NOERROR
    assert response.answer[0].rdtype == dns.rdatatype.SOA


def test_override_returns_configured_address():
    response = query(OVERRIDE_NAME, "A")

    assert response.rcode() == dns.rcode.NOERROR
    assert response.answer[0][0].address == "172.105.26.76"


def test_ordinary_in_zone_name_returns_nodata_without_crashing():
    response = query("ordinary.npub.openproof.org", "A")

    assert response.rcode() == dns.rcode.NOERROR
    assert not response.answer
    assert response.authority[0].rdtype == dns.rdatatype.SOA


def test_record_tags_are_parsed_and_invalid_rows_are_ignored():
    records = parse_into_dns_records(
        [
            ["record", "a", "", "192.0.2.1", "60"],
            ["not-a-record", "TXT", "", "ignored", "60"],
            ["record", "TXT", "", "hello", "invalid-ttl"],
        ]
    )

    assert records == [
        {"type": "A", "name": "", "value": "192.0.2.1", "ttl": 60},
        {"type": "TXT", "name": "", "value": "hello", "ttl": 300},
    ]


def test_invalid_npub_is_rejected():
    assert npub_to_hex_pubkey("npub-not-valid") is None
