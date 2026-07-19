import asyncio
import json
import logging
import secrets
import threading
from typing import Any, Optional

import aiohttp
import bech32

from cache import get_profile_cache, put_profile_cache, put_records
from settings import get_settings


settings = get_settings()
log = logging.getLogger("nostr")

_QTYPE_TO_STR = {
    1: "A",
    16: "TXT",
    28: "AAAA",
    255: "ANY",
}
_NPUB_LOOKUP_DEADLINE = 2.0


def npub_to_hex_pubkey(npub: str) -> Optional[str]:
    """Decode an npub into a 32-byte lowercase public key."""
    try:
        hrp, data = bech32.bech32_decode(npub)
        if hrp is None or hrp.lower() != "npub" or data is None:
            return None
        decoded = bech32.convertbits(data, 5, 8, False)
        if decoded is None or len(decoded) != 32:
            return None
        return bytes(decoded).hex()
    except Exception:
        return None


async def _query_relay(
    session: aiohttp.ClientSession,
    relay: str,
    filters: list[dict[str, Any]],
    timeout: float,
) -> list[dict[str, Any]]:
    """Run a one-shot NIP-01 query against one relay."""
    subscription_id = secrets.token_hex(8)
    events: list[dict[str, Any]] = []
    deadline = asyncio.get_running_loop().time() + timeout

    try:
        async with session.ws_connect(relay, heartbeat=20) as websocket:
            await websocket.send_json(["REQ", subscription_id, *filters])

            while True:
                remaining = deadline - asyncio.get_running_loop().time()
                if remaining <= 0:
                    break
                message = await asyncio.wait_for(websocket.receive(), timeout=remaining)

                if message.type == aiohttp.WSMsgType.TEXT:
                    payload = json.loads(message.data)
                    if not isinstance(payload, list) or not payload:
                        continue
                    if payload[0] == "EOSE" and payload[1] == subscription_id:
                        break
                    if (
                        payload[0] == "EVENT"
                        and payload[1] == subscription_id
                        and isinstance(payload[2], dict)
                    ):
                        events.append(payload[2])
                elif message.type in {
                    aiohttp.WSMsgType.CLOSED,
                    aiohttp.WSMsgType.CLOSE,
                    aiohttp.WSMsgType.ERROR,
                }:
                    break

            await websocket.send_json(["CLOSE", subscription_id])
    except (TimeoutError, asyncio.TimeoutError):
        log.debug("Nostr relay timed out: %s", relay)
    except Exception as exc:
        log.debug("Nostr relay query failed for %s: %s", relay, exc)

    return events


async def query_nostr_events(
    filters: list[dict[str, Any]], timeout: Optional[float] = None
) -> list[dict[str, Any]]:
    """Query all configured relays and deduplicate events by event id."""
    query_timeout = timeout if timeout is not None else settings.NOSTR_FETCH_TIMEOUT
    client_timeout = aiohttp.ClientTimeout(total=query_timeout + 1.0)

    async with aiohttp.ClientSession(timeout=client_timeout) as session:
        results = await asyncio.gather(
            *(
                _query_relay(session, relay, filters, query_timeout)
                for relay in settings.NOSTR_RELAYS
            )
        )

    events_by_id: dict[str, dict[str, Any]] = {}
    for relay_events in results:
        for event in relay_events:
            event_id = event.get("id")
            if isinstance(event_id, str):
                events_by_id[event_id] = event

    return sorted(
        events_by_id.values(),
        key=lambda event: int(event.get("created_at", 0)),
        reverse=True,
    )


def parse_into_dns_records(raw_records: list[list[Any]]) -> list[dict[str, Any]]:
    """Parse ["record", TYPE, NAME, VALUE, ..., TTL] event tags."""
    records: list[dict[str, Any]] = []
    for row in raw_records:
        if not isinstance(row, list) or len(row) < 4 or row[0] != "record":
            continue

        try:
            ttl = int(row[-1])
        except (TypeError, ValueError):
            ttl = 300

        records.append(
            {
                "type": str(row[1]).upper(),
                "name": str(row[2]),
                "value": str(row[3]),
                "ttl": ttl,
            }
        )
    return records


async def lookup_npub_records_tuples(
    npub: str, qtype: int
) -> list[tuple[str, str, int]]:
    """Return DNS tuples published as kind 11111 events by an npub."""
    npub_hex = npub_to_hex_pubkey(npub)
    wanted_type = _QTYPE_TO_STR.get(qtype)
    if npub_hex is None or wanted_type is None:
        return []

    events = await query_nostr_events(
        [
            {
                "limit": 64,
                "authors": [npub_hex],
                "kinds": [settings.KIND_DNS],
            }
        ]
    )

    records: list[tuple[str, str, int]] = []
    seen: set[tuple[str, str]] = set()
    for event in events:
        for record in parse_into_dns_records(event.get("tags", [])):
            rtype = record["type"]
            value = record["value"]
            if wanted_type != "ANY" and rtype != wanted_type:
                continue
            identity = (rtype, value)
            if identity in seen:
                continue
            seen.add(identity)
            records.append((rtype, value, int(record["ttl"])))

    return records


async def lookup_npub_records(npub: str, qtype: int):
    return await lookup_npub_records_tuples(npub, qtype)


async def lookup_npub_a_first(npub: str, qtype: int):
    records = await lookup_npub_records_tuples(npub, 255)
    a_records = [record for record in records if record[0] == "A"]
    wanted_type = _QTYPE_TO_STR.get(qtype)
    if wanted_type == "ANY":
        wanted_records = records
    else:
        wanted_records = [record for record in records if record[0] == wanted_type]
    return a_records, wanted_records


async def _fetch_any_with_timeout(npub: str):
    try:
        return await asyncio.wait_for(
            lookup_npub_records_tuples(npub, 255),
            timeout=_NPUB_LOOKUP_DEADLINE,
        )
    except Exception as exc:
        log.debug("Npub lookup failed for %s: %s", npub, exc)
        return []


async def _npub_a_first_with_timeout(npub: str, qtype: int):
    try:
        return await asyncio.wait_for(
            lookup_npub_a_first(npub, qtype), timeout=_NPUB_LOOKUP_DEADLINE
        )
    except Exception:
        return [], []


async def _npub_fetch_all_with_timeout(npub: str):
    return await _fetch_any_with_timeout(npub)


def _bg_refresh(npub: str, fqdn: str):
    def _run():
        records = asyncio.run(_fetch_any_with_timeout(npub))
        if records:
            put_records(fqdn, records)

    threading.Thread(target=_run, daemon=True).start()


def fetch_any_sync(npub: str, timeout: float):
    try:
        return asyncio.run(
            asyncio.wait_for(lookup_npub_records_tuples(npub, 255), timeout=timeout)
        )
    except Exception as exc:
        log.debug("Npub lookup failed for %s: %s", npub, exc)
        return []


async def fetch_any_sync_2(npub: str, timeout: float):
    return await asyncio.wait_for(
        lookup_npub_records_tuples(npub, 255), timeout=timeout
    )


async def lookup_npub_profile(npub_hex: str, service_request: str):
    """Return a kind 0 profile field as a TXT value."""
    cached, time_left = get_profile_cache(npub_hex, service_request)
    if cached is not None:
        return cached, time_left

    events = await query_nostr_events(
        [{"limit": 1, "authors": [npub_hex], "kinds": [0]}]
    )
    service_answer = None
    if events:
        try:
            profile = json.loads(events[0].get("content", "{}"))
            service_answer = profile.get(service_request.lstrip("_"))
        except (TypeError, ValueError, json.JSONDecodeError):
            service_answer = None

    txt_record = str(service_answer or "")
    put_profile_cache(npub_hex, service_request, txt_record, ttl=3600)
    return txt_record, 3600
