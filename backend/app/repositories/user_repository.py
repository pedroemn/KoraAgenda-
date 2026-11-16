"""Repositórios de usuários: contrato abstrato + implementação em memória."""

from abc import ABC, abstractmethod

from app.models.user import User


class UserRepository(ABC):
    """Contrato que qualquer armazenamento de usuários deve cumprir."""

    @abstractmethod
    def add(self, user: User) -> User: ...

    @abstractmethod
    def get_by_id(self, user_id: str) -> User | None: ...

    @abstractmethod
    def get_by_email(self, email: str) -> User | None: ...

    @abstractmethod
    def list_all(self) -> list[User]: ...

    @abstractmethod
    def update(self, user: User) -> User: ...

    @abstractmethod
    def delete(self, user_id: str) -> bool: ...


class InMemoryUserRepository(UserRepository):
    def __init__(self) -> None:
        self._users: dict[str, User] = {}

    def add(self, user: User) -> User:
        self._users[user.id] = user
        return user

    def get_by_id(self, user_id: str) -> User | None:
        return self._users.get(user_id)

    def get_by_email(self, email: str) -> User | None:
        return next((u for u in self._users.values() if u.email == email), None)

    def list_all(self) -> list[User]:
        return sorted(self._users.values(), key=lambda u: u.created_at)

    def update(self, user: User) -> User:
        self._users[user.id] = user
        return user

    def delete(self, user_id: str) -> bool:
        return self._users.pop(user_id, None) is not None
