#!/usr/bin/env python3
import argparse
import dns.resolver
import dns.exception

def query_record(name: str, qtype: str, server: str = None):
    resolver = dns.resolver.Resolver()
    if server:
        resolver.nameservers = [server]
    try:
        answers = resolver.resolve(name, qtype)
    except dns.resolver.NoAnswer:
        print(f"No {qtype} record found for {name}")
        return
    except dns.resolver.NXDOMAIN:
        print(f"{name} does not exist (NXDOMAIN)")
        return
    except dns.resolver.LifetimeTimeout:
        print(f"Query timed out for {name} {qtype}")
        return
    except Exception as e:
        print(f"Error querying {name} {qtype}: {e}")
        return

    for rdata in answers:
        # rdata.to_text() gives the record content, e.g. IP or text
        print(f"{name} {qtype} {rdata.to_text()} (TTL {answers.rrset.ttl})")

def main():
    parser = argparse.ArgumentParser(description="Simple DNS query tool (like dig)")
    parser.add_argument("name", help="Domain name to query (e.g. example.com)")
    parser.add_argument("-t", "--type", default="A", help="Record type (A, TXT, AAAA, CAA, NS, etc.)")
    parser.add_argument("-s", "--server", help="Optional DNS server to query (e.g. 1.1.1.1)")
    args = parser.parse_args()

    name = args.name
    qtype = args.type.upper()
    server = args.server

    query_record(name, qtype, server)

if __name__ == "__main__":
    main()