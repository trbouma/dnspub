# dnspub

DNS Name server for nostr npubs

This project is a complement to [no-dns](https://gitworkshop.dev/arjen@swissdash.site/no-dns)

The idea is to extend DNS (and DNSSEC) to provide a freedom leaf - a namespace where any npub can be resolved. `subdomain.[npub].delegated_domain`

For example:
 - https://npub1w3megrmxlu7yws0xfzasrvd4k6nf56dp4kvlp7uqr877a3xtzgnqdzunas.npub.openproof.org

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
dig @127.0.0.1 -p 5353 npub.openproof.org SOA
dig @127.0.0.1 -p 5353 <npub>.npub.openproof.org A
dig +tcp @127.0.0.1 -p 5353 <npub>.npub.openproof.org A
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
dig @127.0.0.1 -p 5353 npub.openproof.org SOA
dig +tcp @127.0.0.1 -p 5353 npub.openproof.org SOA
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
PUBLIC_IP=127.0.0.1
NOSTR_FETCH_TIMEOUT=1.0
NOSTR_RELAYS=["wss://relay.damus.io","wss://nos.lol"]
CACHE_ACTIVATED=true
DB_PATH=data/npubcache.sqlite3
```

For a Poetry-based server deployment:

```bash
poetry install --only main
poetry run dnspub
```
