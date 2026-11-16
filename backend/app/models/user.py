"""Entidade de usuário."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import uuid4


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class User:
    name: str
    email: str
    phone: str
    password_hash: str
    id: str = field(default_factory=lambda: str(uuid4()))
    is_active: bool = True
    created_at: datetime = field(default_factory=_utc_now)
    updated_at: datetime = field(default_factory=_utc_now)

    def update_profile(
        self,
        name: str | None = None,
        email: str | None = None,
        phone: str | None = None,
    ) -> None:
        """Altera só os campos informados (valores já validados)."""
        if name is not None:
            self.name = name
        if email is not None:
            self.email = email
        if phone is not None:
            self.phone = phone
        self._touch()

    def change_password_hash(self, password_hash: str) -> None:
        self.password_hash = password_hash
        self._touch()

    def deactivate(self) -> None:
        self.is_active = False
        self._touch()

    def to_public(self) -> dict:
        """Dados seguros para exibir (nunca expõe o hash da senha)."""
        return {
            "id": self.id,
            "name": self.name,
            "email": self.email,
            "phone": self.phone,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }

    def _touch(self) -> None:
        self.updated_at = _utc_now()
