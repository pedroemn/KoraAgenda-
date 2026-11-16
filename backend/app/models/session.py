"""Sessão de login."""

from dataclasses import dataclass
from datetime import datetime, timedelta


@dataclass
class Session:
    token: str
    user_id: str
    created_at: datetime
    expires_at: datetime

    @classmethod
    def open(cls, token: str, user_id: str, now: datetime, ttl: timedelta) -> "Session":
        return cls(token=token, user_id=user_id, created_at=now, expires_at=now + ttl)

    def is_expired(self, now: datetime) -> bool:
        return now >= self.expires_at
