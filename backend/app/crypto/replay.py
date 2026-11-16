 
import json
import os
from datetime import datetime, timedelta
from pathlib import Path

from app.core.config import MESSAGE_CLOCK_SKEW_SECONDS, MESSAGE_MAX_AGE_MINUTES
from app.core.exceptions import CryptoError, MessageIntegrityError


class ReplayGuard:
    def __init__(
        self,
        *,
        max_age: timedelta = timedelta(minutes=MESSAGE_MAX_AGE_MINUTES),
        clock_skew: timedelta = timedelta(seconds=MESSAGE_CLOCK_SKEW_SECONDS),
        storage_path: Path | None = None,
    ) -> None:
        self._max_age = max_age
        self._clock_skew = clock_skew
        self._path = storage_path
        self._seen: dict[str, datetime] = self._load()

    # Propriedade em vez de __len__: com __len__, um guard vazio seria "falso"
    # e um `guard or ReplayGuard()` descartaria o registro silenciosamente.
    @property
    def remembered_count(self) -> int:
        return len(self._seen)

    def check_and_remember(self, message_id: str, created_at: datetime, now: datetime) -> None:
        if created_at.tzinfo is None:
            raise MessageIntegrityError("Data da mensagem sem fuso horário.")
        if created_at > now + self._clock_skew:
            raise MessageIntegrityError("Mensagem com data no futuro.")
        if now - created_at > self._max_age:
            raise MessageIntegrityError("Mensagem antiga demais (fora da janela de validade).")

        self._purge(now)
        if message_id in self._seen:
            raise MessageIntegrityError("Mensagem repetida (replay) rejeitada.")
        self._seen[message_id] = created_at
        self._save()

    def _purge(self, now: datetime) -> None:
        limit = now - self._max_age
        self._seen = {mid: ts for mid, ts in self._seen.items() if ts >= limit}

    def _load(self) -> dict[str, datetime]:
        if self._path is None or not self._path.exists():
            return {}
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
            return {str(mid): datetime.fromisoformat(ts) for mid, ts in data.items()}
        except (ValueError, TypeError, AttributeError) as exc:
            # Falha FECHADA: sem saber o que já foi aceito, não aceita nada.
            raise CryptoError("Registro anti-replay corrompido.") from exc

    def _save(self) -> None:
        if self._path is None:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self._path.with_name(self._path.name + ".tmp")
        temporary.write_text(
            json.dumps({mid: ts.isoformat() for mid, ts in self._seen.items()}),
            encoding="utf-8",
        )
        os.replace(temporary, self._path)  # troca atômica: nunca fica meio gravado
