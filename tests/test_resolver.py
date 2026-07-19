import dns.message
import dns.rcode
import dns.rdatatype

import npubresolver
from nostrdns import npub_to_hex_pubkey, parse_into_dns_records
from npubresolver import NS_HOST, ZONE, build_response, get_public_ip


def query(name: str, record_type: str):
    request = dns.message.make_query(name, record_type)
    return dns.message.from_wire(build_response(request.to_wire()))


def test_zone_apex_returns_soa():
    response = query(ZONE, "SOA")

    assert response.rcode() == dns.rcode.NOERROR
    assert response.answer[0].rdtype == dns.rdatatype.SOA


def test_zone_apex_returns_nameserver_and_glue():
    response = query(ZONE, "NS")

    assert response.rcode() == dns.rcode.NOERROR
    assert str(response.answer[0][0].target) == NS_HOST
    assert response.additional[0][0].address == get_public_ip()


def test_ordinary_in_zone_name_returns_nodata_without_crashing():
    response = query(f"ordinary.{ZONE}", "A")

    assert response.rcode() == dns.rcode.NOERROR
    assert not response.answer
    assert response.authority[0].rdtype == dns.rdatatype.SOA


def test_outside_zone_is_refused():
    response = query("example.com", "A")

    assert response.rcode() == dns.rcode.REFUSED
    assert not response.answer


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


def test_public_ip_can_be_discovered(monkeypatch):
    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def read(self):
            return b"203.0.113.10\n"

    monkeypatch.setattr(npubresolver.settings, "PUBLIC_IP", "auto")
    monkeypatch.setattr(
        npubresolver.urllib.request,
        "urlopen",
        lambda url, timeout: FakeResponse(),
    )
    get_public_ip.cache_clear()

    try:
        assert get_public_ip() == "203.0.113.10"
    finally:
        get_public_ip.cache_clear()
