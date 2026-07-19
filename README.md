# dnspub

DNS Name server for nostr npubs

This project is a complement to [no-dns](https://gitworkshop.dev/arjen@swissdash.site/no-dns)

The idea is to extend DNS (and DNSSEC) to provide a freedom leaf - a namespace where any npub can be resolved. `subdomain.[npub].delegated_domain`

For example:
 - `npub1example.dnspub.xyz`

## Local development

The server uses Python 3.12 and Poetry. It listens on both UDP and TCP.

```bash
poetry env use python3.12
poetry install
poetry run pytest
poetry run dnspub --host 127.0.0.1 --port 5353
```

Query the local server from another terminal:

```bash
dig @127.0.0.1 -p 5353 dnspub.xyz SOA
dig @127.0.0.1 -p 5353 <npub>.dnspub.xyz A
dig +tcp @127.0.0.1 -p 5353 <npub>.dnspub.xyz A
```

Port 53 normally requires elevated privileges. Use port 5353 for development.

## Docker Compose

Build and start the resolver in the background:

```bash
docker compose up --build -d
docker compose logs -f dnspub
```

By default, Compose publishes DNS on `127.0.0.1:5353` for both UDP and TCP.

```bash
dig @127.0.0.1 -p 5353 dnspub.xyz SOA
dig +tcp @127.0.0.1 -p 5353 dnspub.xyz SOA
```

Stop the service while preserving its cache volume:

```bash
docker compose down
```

Set `DNS_BIND_ADDRESS`, `DNS_HOST_PORT`, and other application settings in
`.env` when different values are required.

## Configuration

Settings can be supplied in `.env`. Useful values include:

```dotenv
DNS_HOST=0.0.0.0
DNS_PORT=53
PUBLIC_IP=auto
PUBLIC_IP_DISCOVERY_URL=https://api.ipify.org
PUBLIC_IP_DISCOVERY_TIMEOUT=3.0
ZONE=dnspub.xyz.
NS_HOST=ns1.dnspub.xyz.
SOA_RNAME=hostmaster.dnspub.xyz.
SOA_SERIAL=2026071901
NOSTR_FETCH_TIMEOUT=1.0
NOSTR_RELAYS=["wss://relay.damus.io","wss://nos.lol"]
CACHE_ACTIVATED=true
DB_PATH=data/npubcache.sqlite3
```

Set `PUBLIC_IP=auto` to discover and validate the server's public IPv4 address
at startup. Set an explicit IPv4 address to avoid relying on the external
discovery service.

`ZONE` is the only authoritative zone served by the process. Use
`ZONE=npub.dnspub.xyz.` if only that subdomain is delegated. Increment
`SOA_SERIAL` whenever authoritative zone metadata changes.

For a Poetry-based server deployment:

```bash
poetry install --only main
poetry run dnspub
```
