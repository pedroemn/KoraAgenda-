"""Repositórios de sessões: contrato abstrato + implementação em memória."""

from abc import ABC, abstractmethod

from app.models.session import Session


class SessionRepository(ABC):
    """Contrato que qualquer armazenamento de sessões deve cumprir."""

    @abstractmethod
    def add(self, session: Session) -> Session: ...

    @abstractmethod
    def get(self, token: str) -> Session | None: ...

    @abstractmethod
    def delete(self, token: str) -> bool: ...

    @abstractmethod
    def delete_by_user(self, user_id: str) -> int: ...


class InMemorySessionRepository(SessionRepository):
    def __init__(self) -> None:
        self._sessions: dict[str, Session] = {}

    def add(self, session: Session) -> Session:
        self._sessions[session.token] = session
        return session

    def get(self, token: str) -> Session | None:
        return self._sessions.get(token)

    def delete(self, token: str) -> bool:
        return self._sessions.pop(token, None) is not None

    def delete_by_user(self, user_id: str) -> int:
        tokens = [t for t, s in self._sessions.items() if s.user_id == user_id]
        for token in tokens:
            del self._sessions[token]
        return len(tokens)
