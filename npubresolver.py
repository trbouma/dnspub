#!/usr/bin/env python3
import socket, threading
import struct
import logging
from monstr.encrypt import Keys
import bech32
import asyncio

import signal
import sys

from nostrdns import npub_to_hex_pubkey, lookup_npub_records, lookup_npub_records_tuples, Settings, lookup_npub_a_first, _npub_a_first_with_timeout, _npub_fetch_all_with_timeout, _fetch_any_with_timeout, _bg_refresh
import urllib.request


from cache import init_cache, get_records, put_records, purge_expired
init_cache()


def get_public_ip() -> str:
    try:
        with urllib.request.urlopen("https://api.ipify.org") as resp:
            return resp.read().decode().strip()
    except Exception:
        return "127.0.0.1"  # fallback

# ---- logging ----
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
log = logging.getLogger("dns")

# ---- monstr (for npub validation) ----


def is_valid_npub(label: str) -> bool:
    """
    Validate a string as a Nostr npub (bech32).
    Requires HRP 'npub' and a 32-byte decoded payload.
    """
    if not isinstance(label, str) or not label:
        return False
    try:
        hrp, data = bech32.bech32_decode(label)
        if hrp is None or data is None:
            return False
        if hrp.lower() != "npub":
            return False
        decoded = bech32.convertbits(data, 5, 8, False)  # returns a list of ints
        return decoded is not None and len(decoded) == 32
    except Exception:
        return False

def inspect_fqdn_for_npub(fqdn: str):
    """
    Inspect an FQDN for a valid npub label.

    Args:
        fqdn (str): Fully-qualified domain name (with or without trailing dot).

    Returns:
        tuple:
          - is_valid (bool): True if a valid npub was found
          - labels (list[str]): split fqdn labels
          - pos (int|None): index of the valid npub in labels, else None
          - npub_subdomain (str|None): subdomain string left of the npub, else None
    """
    # Normalize and strip trailing dot
    fqdn = fqdn.strip().lower().rstrip(".")
    labels = fqdn.split(".")

    for idx, label in enumerate(labels):
        if is_valid_npub(label):  # your existing validator
            npub_subdomain = ".".join(labels[:idx]) if idx > 0 else None
            return True, labels, idx, npub_subdomain

    return False, labels, None, None


# Zone SOA config
ZONE   = "npub.openproof.org."
MNAME  = "ns1.npub.openproof.org."           # primary nameserver
RNAME  = "hostmaster.npub.openproof.org."    # admin email with '.' instead of '@'
SERIAL = 2025092701                     # bump when you change zone data
REFRESH = 3600
RETRY   = 600
EXPIRE  = 604800
MINIMUM = 3600
SOA_TTL = 3600


NS    = ["ns1.npub.openproof.org."]          # you can add ns2 later
GLUE = {"ns1.npub.openproof.org.": get_public_ip()}


# -------------------------------
# Local records
# -------------------------------
LOCAL_DATA = {
    "example.com.": [("A", "93.184.216.34", 300)],
    "local.test.":  [("TXT", "hello from local", 60)],
}

# -------------------------------
# Upstream forwarders
# -------------------------------
FORWARDERS = [
    ("1.1.1.1", 53),
    ("8.8.8.8", 53),
]
FORWARD_TIMEOUT = 2.0

# ---- multi-zone config ----
ZONES = {
    "openproof.org.": {
        "ns": ["ns1.openproof.org."],
        "glue_a": {"ns1.openproof.org.": "15.235.3.226"},
        "soa": {
            "mname": "ns1.openproof.org.",
            "rname": "hostmaster.openproof.org.",
            "serial": 2025092801,
            "refresh": 3600, "retry": 600, "expire": 604800, "minimum": 3600, "ttl": 3600
        },
    },
    "npub.openproof.org.": {
    "soa": {  # your existing SOA fields
        "mname": "ns1.openproof.org.",
        "rname": "hostmaster.openproof.org.",
        "serial": 2025092901, "refresh": 3600, "retry": 600, "expire": 604800, "minimum": 3600, "ttl": 3600
    },
    "ns": ["ns1.openproof.org."],
    "glue_a": {"ns1.openproof.org.": "15.235.3.226"},
    # NEW: explicit CAA that authorizes Let's Encrypt and no wildcards by default
    "caa": [
        (0, "issue", "letsencrypt.org", 3600),
        # (0, "issuewild", ";", 3600),  # uncomment if you want to explicitly *deny* wildcards
        # (0, "iodef", "mailto:hostmaster@openproof.org", 3600),
    ],
},
}

def find_zone(qname: str) -> str | None:
    """Return the longest matching zone apex for qname."""
    q = qname.rstrip(".") + "."
    best = None
    for zone in ZONES.keys():
        if q.endswith(zone) and (best is None or len(zone) > len(best)):
            best = zone
    return best



# -------------------------------
# DNS wire helpers
# -------------------------------
def encode_name(name: str) -> bytes:
    if not name.endswith("."):
        name += "."
    out = b""
    for label in name[:-1].split("."):
        b = label.encode()
        out += struct.pack("B", len(b)) + b
    return out + b"\x00"

def parse_question(msg: bytes):
    i = 12
    labels = []
    while True:
        ln = msg[i]; i += 1
        if ln == 0: break
        labels.append(msg[i:i+ln].decode()); i += ln
    qtype, qclass = struct.unpack(">HH", msg[i:i+4]); i += 4
    qname = ".".join(labels)+"."
    return qname, qtype, qclass, i

def build_flags(req_flags, rcode=0, aa=False, ra=True):
    rf = struct.unpack(">H", req_flags)[0]
    rd = rf & 0x0100
    flags = 0x8000               # QR=1
    if aa: flags |= 0x0400       # AA
    flags |= rd                  # mirror RD
    if ra: flags |= 0x0080       # RA
    flags |= rcode
    return struct.pack(">H", flags)

def rr_ns(name: str, host: str, ttl: int = 3600) -> bytes:
    rdata = encode_name(host)
    return encode_name(name) + struct.pack(">HHI", 2, 1, ttl) + struct.pack(">H", len(rdata)) + rdata


def rr_header(name, rtype, ttl, rdata):
    return encode_name(name) + struct.pack(">HHI", rtype, 1, ttl) + struct.pack(">H", len(rdata)) + rdata

def rr_a(name, ip, ttl):    return rr_header(name, 1, ttl, socket.inet_aton(ip))

def rr_aaaa(name: str, ipv6: str, ttl: int) -> bytes:
    """
    Build a DNS AAAA resource record.

    Args:
        name (str): FQDN ending with a dot, e.g. "host.example.com."
        ipv6 (str): IPv6 address string, e.g. "2001:db8::1"
        ttl (int): TTL in seconds

    Returns:
        bytes: wire-format DNS AAAA RR
    """
    # compress address into 16 bytes
    try:
        ipv6_bytes = socket.inet_pton(socket.AF_INET6, ipv6)
    except OSError:
        raise ValueError(f"Invalid IPv6 address: {ipv6}")

    rtype = 28      # AAAA
    rclass = 1      # IN
    rdlength = len(ipv6_bytes)

    return (
        encode_name(name)
        + struct.pack(">HHI", rtype, rclass, ttl)
        + struct.pack(">H", rdlength)
        + ipv6_bytes
    )

def rr_txt(name, text, ttl):
    b = text.encode(); b = b[:255]
    return rr_header(name, 16, ttl, struct.pack("B", len(b))+b)

def rr_soa(qname: str, mname: str, rname: str,
           serial: int, refresh: int, retry: int,
           expire: int, minimum: int, ttl: int = 3600) -> bytes:
    def _enc(name: str) -> bytes:
        parts = name.rstrip(".").split(".")
        return b"".join(bytes([len(p)]) + p.encode() for p in parts) + b"\x00"

    rdata = (
        _enc(mname) +
        _enc(rname) +
        struct.pack(">IIIII", serial, refresh, retry, expire, minimum)
    )
    return (
        _enc(qname) +
        struct.pack(">HHI", 6, 1, ttl) +            # TYPE=SOA, CLASS=IN, TTL
        struct.pack(">H", len(rdata)) + rdata
    )

# -------------------------------
# Forward to upstream
# -------------------------------
def forward_query(req: bytes) -> bytes | None:
    for host, port in FORWARDERS:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(FORWARD_TIMEOUT)
                s.sendto(req, (host, port))
                resp, _ = s.recvfrom(4096)
                return resp
        except Exception as e:
            log.debug(f"forwarder {host}:{port} failed: {e}")
            continue
    return None
def rr_soa(qname: str, mname: str, rname: str,
           serial: int, refresh: int, retry: int,
           expire: int, minimum: int, ttl: int = 3600) -> bytes:
    """
    Build a DNS SOA record.
    
    qname: zone name (e.g., 'supername.app.')
    mname: primary master nameserver (e.g., 'ns1.supername.app.')
    rname: responsible party (e.g., 'hostmaster.supername.app.')
    """
    # Encode names
    def encode_name(name: str) -> bytes:
        parts = name.rstrip('.').split('.')
        out = b''.join(struct.pack("B", len(p)) + p.encode() for p in parts)
        return out + b'\x00'

    rdata = (
        encode_name(mname) +
        encode_name(rname) +
        struct.pack(">IIIII", serial, refresh, retry, expire, minimum)
    )

    return (
        encode_name(qname) +
        struct.pack(">HHI", 6, 1, ttl) +  # type=SOA (6), class=IN (1), ttl
        struct.pack(">H", len(rdata)) +
        rdata
    )

def rr_caa(name: str, flag: int, tag: str, value: str, ttl: int) -> bytes:
    n = encode_name(name)  # your existing encoder

    tag_b = (tag or "").strip().lower().encode("ascii")
    val_b = (value or "").strip().encode("utf-8")

    if not (1 <= len(tag_b) <= 255):
        raise ValueError("CAA tag length must be 1..255")
    if not (0 <= int(flag) <= 255):
        raise ValueError("CAA flag must be 0..255")
    # value is raw bytes; no length octet in wire format for CAA
    # (You may still cap for sanity if you want.)
    if len(val_b) > 1024:  # arbitrary sanity cap
        raise ValueError("CAA value unreasonably long")

    # RDATA = flags(1) + taglen(1) + tag + value  (NO value length byte)
    rdata = struct.pack("!B", int(flag)) + bytes([len(tag_b)]) + tag_b + val_b

    # TYPE=257, CLASS=IN(1), TTL, RDLEN, RDATA
    return n + struct.pack(">HHI", 257, 1, int(ttl)) + struct.pack(">H", len(rdata)) + rdata

OVERRIDES = {
    "npub1h9taws9gujwja2weyxzhawfahwqljcm3cs7wjv5vv70dvtx637wsl8rhx0.npub.openproof.org.": {
        "A": ("172.105.26.76", 300),   # <— your Nginx public IPv4
        # only add AAAA if your Nginx listens on 80 over IPv6:
        # "AAAA": ("2001:db8::1", 300), 
        },
    "npub1cwddk7gqlg0l934ensek4ctl7mqg3drd33apv4wg9gr7cnl6gsnsujhrk2.npub.openproof.org.": {
        "A": ("172.105.26.76", 300),   # <— your Nginx public IPv4
        # only add AAAA if your Nginx listens on 80 over IPv6:
        # "AAAA": ("2001:db8::1", 300), 
        },    
}

def normalize_name(name: str) -> str:
    n = (name or "").rstrip(".").lower()
    return n + "."

def rr_opt(udp_payload=1232) -> bytes:
    # NAME=root(0), TYPE=41, CLASS=udp_payload, TTL=0, RDLEN=0
    return b"\x00" + struct.pack(">H H I H", 41, udp_payload, 0, 0)

def negative_nodata(zone: str, req_flags: bytes, tid: bytes, question: bytes, add_opt=True, ra=False) -> bytes:
    """Return NOERROR with SOA in AUTHORITY (RFC 2308), 0 answers."""
    s = ZONES[zone]["soa"]
    auth = rr_soa(zone, s["mname"], s["rname"], s["serial"], s["refresh"],
                  s["retry"], s["expire"], s["minimum"], s["ttl"])
    flags = build_flags(req_flags, rcode=0, aa=True, ra=ra)
    ar = rr_opt() if add_opt else b""
    header = tid + flags + struct.pack(">HHHH", 1, 0, 1, 1 if ar else 0)
    return header + question + auth + ar

def positive_answer(tid, req_flags, question, *, answers=b"", authorities=b"", additionals=b"", aa=True, ra=False, add_opt=True):
    flags = build_flags(req_flags, rcode=0, aa=aa, ra=ra)
    ar = additionals + (rr_opt() if add_opt else b"")
    header = tid + flags + struct.pack(">HHHH", 1, count_rrs(answers), count_rrs(authorities), count_rrs(ar))
    return header + question + answers + authorities + ar

def nodata(zone: str, tid, req_flags, question, *, add_opt=True, ra=False):
    """NOERROR/NODATA with SOA in AUTHORITY (RFC 2308)"""
    s = ZONES[zone]["soa"]
    auth = rr_soa(zone, s["mname"], s["rname"], s["serial"], s["refresh"], s["retry"], s["expire"], s["minimum"], s["ttl"])
    flags = build_flags(req_flags, rcode=0, aa=True, ra=ra)
    ar = rr_opt() if add_opt else b""
    header = tid + flags + struct.pack(">HHHH", 1, 0, 1, 1 if ar else 0)
    return header + question + auth + ar

def zone_ns_authority(zone: str, ttl=3600) -> bytes:
    """Authoritative NS set for AUTHORITY section (helps some resolvers)."""
    return b"".join(rr_ns(zone, ns) for ns in ZONES[zone]["ns"])

# -------------------------------
# Build response
# -------------------------------
def build_response(req: bytes) -> bytes:
    tid, req_flags = req[:2], req[2:4]
    qname, qtype, qclass, qend = parse_question(req)
    question = req[12:qend]

    RA = False
    add_opt = True
    fqdn = normalize_name(qname)

    # ---- OVERRIDES (unchanged) ----
    recs = OVERRIDES.get(fqdn)
    if recs:
        answers = b""
        if qtype in (1, 255) and "A" in recs:
            answers += rr_a(fqdn, recs["A"][0], int(recs["A"][1]))
        if qtype in (28, 255) and "AAAA" in recs:
            answers += rr_aaaa(fqdn, recs["AAAA"][0], int(recs["AAAA"][1]))
        if qtype in (16, 255) and "TXT" in recs:
            answers += rr_txt(fqdn, str(recs["TXT"][0]), int(recs["TXT"][1]))
        if qtype == 28 and "AAAA" not in recs:
            zone = find_zone(fqdn)
            if zone:
                return nodata(zone, tid, req_flags, question, add_opt=add_opt, ra=RA)
        if answers:
            return positive_answer(tid, req_flags, question, answers=answers, aa=True, ra=RA, add_opt=add_opt)

    # ---- Only IN ----
    if qclass != 1:
        flags = build_flags(req_flags, rcode=4, aa=True, ra=RA)  # NOTIMP
        header = tid + flags + struct.pack(">HHHH", 1, 0, 0, 1 if add_opt else 0)
        return header + question + (rr_opt() if add_opt else b"")

    # ---- ZONE HANDLING ----
    zone = find_zone(fqdn)
    if zone:
        z = ZONES[zone]

        # Apex SOA
        if fqdn == zone and qtype in (6, 255):
            s = z["soa"]
            ans = rr_soa(zone, s["mname"], s["rname"], s["serial"], s["refresh"], s["retry"], s["expire"], s["minimum"], s["ttl"])
            return positive_answer(tid, req_flags, question, answers=ans, aa=True, ra=RA, add_opt=add_opt)

        # Apex NS (+glue)
        if fqdn == zone and qtype in (2, 255):
            answers = b"".join(rr_ns(zone, ns) for ns in z["ns"])
            glue_map = z.get("glue_a", {})
            additionals = b"".join(rr_a(h, ip, 3600) for h, ip in glue_map.items() if h in z["ns"])
            return positive_answer(tid, req_flags, question, answers=answers, additionals=additionals, aa=True, ra=RA, add_opt=add_opt)

        # Apex CAA
        if fqdn == zone and qtype in (257, 255):
            caa_list = z.get("caa", [])
            if caa_list:
                answers = b"".join(rr_caa(zone, flag, tag, val, ttl) for (flag, tag, val, ttl) in caa_list)
                return positive_answer(tid, req_flags, question, answers=answers, aa=True, ra=RA, add_opt=add_opt)
            return nodata(zone, tid, req_flags, question, add_opt=add_opt, ra=RA)

        # In-zone glue host A
        if qtype in (1, 255) and fqdn in z.get("glue_a", {}):
            ans = rr_a(fqdn, z["glue_a"][fqdn], 3600)
            auth = zone_ns_authority(zone)
            return positive_answer(tid, req_flags, question, answers=ans, authorities=auth, aa=True, ra=RA, add_opt=add_opt)

        # ---------- NPUB LEAF HANDLING (moved up BEFORE fallback) ----------
        is_npub,nameparts, offset, npub_subdomain = inspect_fqdn_for_npub(fqdn=fqdn)
        print(f"inspect for npub {is_npub} {nameparts} {offset} {nameparts[offset]} subdomain: {npub_subdomain}")
        # leftmost = fqdn.split(".", 1)[0]
        
        if is_npub:
            npub_to_use = nameparts[offset]
            # CAA at leaf → clean NODATA
            if qtype == 257:
                return nodata(zone, tid, req_flags, question, add_opt=add_opt, ra=RA)

            answers = b""

            # Cache first (A/TXT/AAAA or ALL for ANY)
            if qtype == 255:
                want_types = ["A", "TXT", "AAAA"]
            else:
                want_types = [{1:"A", 16:"TXT", 28:"AAAA"}.get(qtype, None)]
                want_types = [t for t in want_types if t]

            cached_any = False
            for rtype in want_types:
                cached = get_records(fqdn, rtype)
                if cached:
                    cached_any = True
                    for _t, val, ttl in cached:
                        if rtype == "A":   answers += rr_a(fqdn, str(val), int(ttl))
                        if rtype == "TXT": answers += rr_txt(fqdn, str(val), int(ttl))
                        if rtype == "AAAA":answers += rr_aaaa(fqdn, str(val), int(ttl))

            if answers:
                auth = zone_ns_authority(zone)
                return positive_answer(tid, req_flags, question, answers=answers, authorities=auth, aa=True, ra=RA, add_opt=add_opt)

            # is name known in cache at all?
            if not cached_any:
                for probe in ("A", "TXT", "AAAA"):
                    if get_records(fqdn, probe):
                        cached_any = True
                        break

            if cached_any:
                # known name, type not present → NODATA
                return nodata(zone, tid, req_flags, question, add_opt=add_opt, ra=RA)

            # Cold name → one fast ANY fetch + store + serve filtered
            try:
                try:
                    tuples_any = asyncio.run(_npub_fetch_all_with_timeout(npub_to_use))
                except RuntimeError:
                    loop = asyncio.new_event_loop()
                    try:
                        tuples_any = loop.run_until_complete(_npub_fetch_all_with_timeout(npub_to_use))
                    finally:
                        loop.close()
            except Exception as e:
                print(f"[ERR] npub ANY runner: {e}")
                tuples_any = []

            if tuples_any:
                put_records(fqdn, tuples_any)
                if qtype in (1, 255):
                    for t, v, ttl in tuples_any:
                        if t.upper() == "A":    answers += rr_a(fqdn, str(v), int(ttl))
                if qtype in (16, 255):
                    for t, v, ttl in tuples_any:
                        if t.upper() == "TXT":  answers += rr_txt(fqdn, str(v), int(ttl))
                if qtype in (28, 255):
                    for t, v, ttl in tuples_any:
                        if t.upper() == "AAAA": answers += rr_aaaa(fqdn, str(v), int(ttl))

                if answers:
                    auth = zone_ns_authority(zone)
                    _bg_refresh(npub_to_use, fqdn)
                    return positive_answer(tid, req_flags, question, answers=answers, authorities=auth, aa=True, ra=RA, add_opt=add_opt)

            # Still nothing → authoritative NOERROR/NODATA
            return nodata(zone, tid, req_flags, question, add_opt=add_opt, ra=RA)

        # ---------- END NPUB HANDLING ----------

        # Final in-zone fallback for anything else:
        return nodata(zone, tid, req_flags, question, add_opt=add_opt, ra=RA)

    # ---- outside our zones → REFUSED (authoritative only) ----
    flags = build_flags(req_flags, rcode=5, aa=False, ra=RA)
    header = tid + flags + struct.pack(">HHHH", 1, 0, 0, 1 if add_opt else 0)
    return header + question + (rr_opt() if add_opt else b"")


def count_rrs(rr_blob: bytes) -> int:
    i = 0; cnt = 0
    while i < len(rr_blob):
        # NAME
        while True:
            if i >= len(rr_blob): return cnt
            ln = rr_blob[i]; i += 1
            if ln == 0: break
            i += ln
        if i + 10 > len(rr_blob): return cnt
        _, _, _, rdlen = struct.unpack(">HHIH", rr_blob[i:i+10])
        i += 10 + rdlen
        cnt += 1
    return cnt

def handle_tcp_client(conn, addr):
    try:
        # TCP DNS uses a 2-byte length prefix
        l = conn.recv(2)
        if len(l) < 2:
            return
        ln = int.from_bytes(l, "big")
        req = conn.recv(ln)
        resp = build_response(req)
        conn.send(len(resp).to_bytes(2, "big") + resp)
    finally:
        conn.close()

def start_dns_tcp(host="0.0.0.0", port=53):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen(100)
    print(f"[DNS] listening on {host}:{port} (TCP)")
    try:
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_tcp_client, args=(conn, addr), daemon=True).start()
    finally:
        s.close()

# -------------------------------
# UDP server
# -------------------------------
def start_dns_server(host="0.0.0.0", port=53):
    settings = Settings()
    print(f" Settings: {settings}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # allow quick restart
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    except Exception:
        pass
    sock.bind((host, port))
    # allow loop to wake up and handle shutdown
    sock.settimeout(1.0)

    print(f"[DNS] listening on {host}:{port} (UDP)")

    # Make SIGTERM behave like Ctrl-C (useful for docker stop)
    def _term_handler(signum, frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, _term_handler)

    

    try:
        while True:
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                continue  # check again (and allows Ctrl-C to be processed)
            except KeyboardInterrupt:
                raise
            except Exception as e:
                # ignore transient recv errors and keep serving
                # print(f"recv error: {e}")
                continue

            try:
                resp = build_response(data)
            except KeyboardInterrupt:
                raise
            except Exception as e:
                # FORMERR fallback
                tid = data[:2] if len(data) >= 2 else b"\x00\x00"
                flags = build_flags(data[2:4] if len(data) >= 4 else b"\x00\x00", rcode=1, aa=False, ra=True)
                resp = tid + flags + b"\x00\x00\x00\x00\x00\x00\x00\x00"

            try:
                sock.sendto(resp, addr)
            except Exception:
                pass

    except KeyboardInterrupt:
        print("\n[DNS] shutting down...")
    finally:
        try:
            sock.close()
        except Exception:
            pass
        print("[DNS] socket closed")

if __name__ == "__main__":
    threading.Thread(target=start_dns_tcp, daemon=True).start()
    start_dns_server()  # your UDP loop
