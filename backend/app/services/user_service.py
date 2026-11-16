"""CRUD de usuários e troca de senha."""

from app.core.exceptions import AuthenticationError, ConflictError, NotFoundError
from app.core.security import PasswordHasher
from app.models.user import User
from app.repositories.session_repository import SessionRepository
from app.repositories.user_repository import UserRepository
from app.utils.validators import UserValidator


class UserService:
    def __init__(
        self,
        users: UserRepository,
        sessions: SessionRepository,
        hasher: PasswordHasher,
        validator: UserValidator,
    ) -> None:
        self._users = users
        self._sessions = sessions
        self._hasher = hasher
        self._validator = validator

    # Create
    def create_user(self, name: str, email: str, phone: str, password: str) -> User:
        name = self._validator.name(name)
        email = self._validator.email(email)
        phone = self._validator.phone(phone)
        password = self._validator.new_password(password)
        self._ensure_email_available(email)

        user = User(
            name=name,
            email=email,
            phone=phone,
            password_hash=self._hasher.hash(password),
        )
        return self._users.add(user)

    # Read
    def get_user(self, user_id: str) -> User:
        user = self._users.get_by_id(user_id)
        if not user:
            raise NotFoundError("Usuário não encontrado.")
        return user

    def list_users(self) -> list[User]:
        return self._users.list_all()

    # Update
    def update_user(
        self,
        user_id: str,
        name: str | None = None,
        email: str | None = None,
        phone: str | None = None,
    ) -> User:
        user = self.get_user(user_id)

        if name is not None:
            name = self._validator.name(name)
        if email is not None:
            email = self._validator.email(email)
            self._ensure_email_available(email, owner_id=user.id)
        if phone is not None:
            phone = self._validator.phone(phone)

        user.update_profile(name=name, email=email, phone=phone)
        return self._users.update(user)

    def change_password(self, user_id: str, current_password: str, new_password: str) -> None:
        user = self.get_user(user_id)
        if not self._hasher.verify(current_password or "", user.password_hash):
            raise AuthenticationError("Senha atual incorreta.")

        new_password = self._validator.new_password(new_password)
        user.change_password_hash(self._hasher.hash(new_password))
        self._users.update(user)
        # Encerra todas as sessões abertas do usuário.
        self._sessions.delete_by_user(user.id)

    # Delete
    def delete_user(self, user_id: str) -> None:
        if not self._users.delete(user_id):
            raise NotFoundError("Usuário não encontrado.")
        self._sessions.delete_by_user(user_id)

    def _ensure_email_available(self, email: str, owner_id: str | None = None) -> None:
        other = self._users.get_by_email(email)
        if other and other.id != owner_id:
            raise ConflictError("Já existe um usuário com este e-mail.")
