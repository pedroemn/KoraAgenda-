"""Validação e normalização dos dados de usuário."""

import re

from app.core.config import Settings
from app.core.exceptions import ValidationError


class UserValidator:
    """Valida e normaliza nome, e-mail, telefone e senha.

    Cada método devolve o valor já normalizado ou lança `ValidationError`.
    """

    _EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    _NON_DIGIT_RE = re.compile(r"\D")
    _LETTER_RE = re.compile(r"[A-Za-z]")
    _DIGIT_RE = re.compile(r"\d")

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or Settings()

    def name(self, name: str) -> str:
        name = " ".join((name or "").split())
        if len(name) < self._settings.name_min_length:
            raise ValidationError(
                f"O nome deve ter pelo menos {self._settings.name_min_length} caracteres."
            )
        if len(name) > self._settings.name_max_length:
            raise ValidationError(
                f"O nome deve ter no máximo {self._settings.name_max_length} caracteres."
            )
        return name

    def email(self, email: str) -> str:
        email = (email or "").strip().lower()
        if not email:
            raise ValidationError("Informe o e-mail.")
        if len(email) > self._settings.email_max_length or not self._EMAIL_RE.match(email):
            raise ValidationError("E-mail inválido.")
        return email

    def phone(self, phone: str) -> str:
        """Mantém só os dígitos (DDD + número, com ou sem código do país)."""
        digits = self._NON_DIGIT_RE.sub("", phone or "")
        if not self._settings.phone_min_digits <= len(digits) <= self._settings.phone_max_digits:
            raise ValidationError("Telefone inválido. Informe DDD + número.")
        return digits

    def new_password(self, password: str) -> str:
        """Regras de força, usadas no cadastro e na troca de senha."""
        password = password or ""
        if len(password) < self._settings.password_min_length:
            raise ValidationError(
                f"A senha deve ter pelo menos {self._settings.password_min_length} caracteres."
            )
        self._check_max_length(password)
        if not self._LETTER_RE.search(password) or not self._DIGIT_RE.search(password):
            raise ValidationError("A senha deve conter letras e números.")
        return password

    def login_password(self, password: str) -> str:
        """No login só checa presença e tamanho máximo (sem regras de força)."""
        password = password or ""
        if not password:
            raise ValidationError("Informe a senha.")
        self._check_max_length(password)
        return password

    def _check_max_length(self, password: str) -> None:
        if len(password) > self._settings.password_max_length:
            raise ValidationError(
                f"A senha deve ter no máximo {self._settings.password_max_length} caracteres."
            )
