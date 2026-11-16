"""Monta as dependências da aplicação (injeção manual).

Ponto único onde os repositórios em memória serão trocados pelos de banco.
"""

from app.core.clock import Clock, SystemClock
from app.core.config import Settings
from app.core.security import (
    Argon2idPasswordHasher,
    Pbkdf2PasswordHasher,
    TokenGenerator,
    UpgradingPasswordHasher,
)
from app.repositories.session_repository import InMemorySessionRepository, SessionRepository
from app.repositories.user_repository import InMemoryUserRepository, UserRepository
from app.services.auth_service import AuthService
from app.services.user_service import UserService
from app.utils.validators import UserValidator


class Container:
    """Cria e guarda os objetos compartilhados da aplicação."""

    def __init__(
        self,
        settings: Settings | None = None,
        clock: Clock | None = None,
        users: UserRepository | None = None,
        sessions: SessionRepository | None = None,
    ) -> None:
        self.settings = settings or Settings()
        self.clock = clock or SystemClock()
        self.users = users or InMemoryUserRepository()
        self.sessions = sessions or InMemorySessionRepository()

        # Argon2id para hashes novos; PBKDF2 só para validar e migrar hashes antigos.
        hasher = UpgradingPasswordHasher(
            current=Argon2idPasswordHasher(
                memory_kib=self.settings.argon2_memory_kib,
                iterations=self.settings.argon2_iterations,
                lanes=self.settings.argon2_lanes,
            ),
            legacy=[Pbkdf2PasswordHasher(self.settings.password_hash_iterations)],
        )
        self.password_hasher = hasher
        validator = UserValidator(self.settings)

        self.user_service = UserService(self.users, self.sessions, hasher, validator)
        self.auth_service = AuthService(
            self.users,
            self.sessions,
            hasher,
            TokenGenerator(),
            validator,
            self.clock,
            self.settings.session_ttl_minutes,
        )
