# settings.py
from functools import lru_cache
from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
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

    # Make these configurable via .env
    ZONE: str = "npub.openproof.org."
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