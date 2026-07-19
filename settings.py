# settings.py
from functools import lru_cache
from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    DNS_HOST: str = "0.0.0.0"
    DNS_PORT: int = 53
    PUBLIC_IP: str = "127.0.0.1"
    PUBLIC_IP_DISCOVERY_URL: str = "https://api.ipify.org"
    PUBLIC_IP_DISCOVERY_TIMEOUT: float = 3.0
    DEBUG_ALWAYS_RELAY: bool = False
    NOSTR_FETCH_TIMEOUT: float = 1.0
    CACHE_ACTIVATED: bool = True
    CACHE_WRITEBACK: bool = True
    NOSTR_RELAYS: List[str] = [
        "wss://relay.damus.io",
        "wss://nos.lol",
        "wss://relay.primal.net",
        "wss://relay.snort.social",
    ]
    KIND_DNS: int = 11111

    # Authoritative zone settings. Names are normalized with a trailing dot.
    ZONE: str = "dnspub.xyz."
    NS_HOST: str = "ns1.dnspub.xyz."
    SOA_RNAME: str = "hostmaster.dnspub.xyz."
    SOA_SERIAL: int = 2026071901
    SOA_REFRESH: int = 3600
    SOA_RETRY: int = 600
    SOA_EXPIRE: int = 604800
    SOA_MINIMUM: int = 3600
    SOA_TTL: int = 3600
    CAA_ISSUER: str = "letsencrypt.org"
    DB_PATH: str = "data/npubcache.sqlite3"

    # Pydantic v2 settings config
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        # Optional: allow nested envs like NOSTR_RELAYS='["wss://a","wss://b"]'
        # If you prefer comma-separated, see the note below.
    )

@lru_cache
def get_settings() -> Settings:
    # Single process-wide instance; evaluated once, then cached.
    return Settings()
