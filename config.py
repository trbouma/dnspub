from pydantic_settings import BaseSettings
from typing import List, Tuple, Optional

class Settings(BaseSettings):
    NOSTR_RELAYS: List = [
        "wss://relay.damus.io",
        "wss://relay.damus.io"
        "wss://nos.lol",
        "wss://relay.primal.net",
        "wss://relay.snort.social"

    ]
    KIND_DNS: int = 11111 # Custom event kind for “DNS record” (choose any free kind you prefer)




    ZONE: str = "npub.openproof.org."
    DB_PATH: str = "data/npubcache.sqlite3"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"