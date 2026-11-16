"""Login, logout e validação de sessão."""

from datetime import timedelta

from app.core.clock import Clock
from app.core.exceptions import AuthenticationError
from app.core.security import PasswordHasher, TokenGenerator
from app.models.session import Session
from app.models.user import User
from app.repositories.session_repository import SessionRepository
from app.repositories.user_repository import UserRepository
from app.utils.validators import UserValidator


class AuthService:
    # Mensagem única para não revelar se o e-mail existe ou não.
    INVALID_CREDENTIALS = "E-mail ou senha inválidos."
    INVALID_SESSION = "Sessão inválida. Faça login novamente."
    EXPIRED_SESSION = "Sessão expirada. Faça login novamente."

    def __init__(
        self,
        users: UserRepository,
        sessions: SessionRepository,
        hasher: PasswordHasher,
        tokens: TokenGenerator,
        validator: UserValidator,
        clock: Clock,
        ttl_minutes: int,
    ) -> None:
        self._users = users
        self._sessions = sessions
        self._hasher = hasher
        self._tokens = tokens
        self._validator = validator
        self._clock = clock
        self._ttl = timedelta(minutes=ttl_minutes)
        # Hash usado quando o e-mail não existe, para que o tempo de resposta
        # seja o mesmo de uma senha errada (evita descobrir e-mails pelo tempo).
        self._dummy_hash = hasher.hash("kora-dummy-password-0")

    def login(self, email: str, password: str) -> Session:
        # 1) Validação de entrada (formato) — erros específicos e seguros.
        email = self._validator.email(email)
        password = self._validator.login_password(password)

        # 2) Validação de credenciais — erro genérico.
        user = self._users.get_by_email(email)
        stored_hash = user.password_hash if user else self._dummy_hash
        password_ok = self._hasher.verify(password, stored_hash)

        if not user or not password_ok:
            raise AuthenticationError(self.INVALID_CREDENTIALS)
        if not user.is_active:
            raise AuthenticationError("Usuário desativado.")

        # 3) Migração transparente: hash legado/fraco é regravado com o
        #    algoritmo atual, aproveitando que só agora temos a senha em mãos.
        if self._hasher.needs_rehash(user.password_hash):
            user.change_password_hash(self._hasher.hash(password))
            self._users.update(user)

        session = Session.open(self._tokens.generate(), user.id, self._clock.now(), self._ttl)
        return self._sessions.add(session)

    def logout(self, token: str) -> None:
        self._sessions.delete(token)

    def get_current_user(self, token: str) -> User:
        session = self._sessions.get(token)
        if not session:
            raise AuthenticationError(self.INVALID_SESSION)
        if session.is_expired(self._clock.now()):
            self._sessions.delete(token)
            raise AuthenticationError(self.EXPIRED_SESSION)

        user = self._users.get_by_id(session.user_id)
        if not user or not user.is_active:
            self._sessions.delete(token)
            raise AuthenticationError(self.INVALID_SESSION)
        return user
