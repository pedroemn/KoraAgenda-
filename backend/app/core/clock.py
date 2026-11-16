"""Fonte de tempo da aplicação.

Abstrair o relógio permite controlar o "agora" nos testes (ex.: expiração de
sessão) sem esperar o tempo passar.
"""

from abc import ABC, abstractmethod
from datetime import datetime, timezone


class Clock(ABC):
    @abstractmethod
    def now(self) -> datetime:
        """Data/hora atual em UTC."""


class SystemClock(Clock):
    def now(self) -> datetime:
        return datetime.now(timezone.utc)
