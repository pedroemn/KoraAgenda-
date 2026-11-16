import unittest
from datetime import datetime, timedelta, timezone

from app.container import Container
from app.core.clock import Clock
from app.core.config import PASSWORD_MAX_LENGTH, Settings
from app.core.exceptions import AuthenticationError, ValidationError


class FakeClock(Clock):
    def __init__(self):
        self.current = datetime(2026, 1, 1, tzinfo=timezone.utc)

    def now(self):
        return self.current


class AuthServiceTest(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        container = Container(Settings(session_ttl_minutes=60), clock=self.clock)
        self.users = container.user_service
        self.auth = container.auth_service
        self.user = self.users.create_user(
            "Lucas Silva", "lucas@email.com", "11987654321", "senha1234"
        )

    def test_login_success_returns_session(self):
        session = self.auth.login("  LUCAS@email.com ", "senha1234")
        self.assertEqual(session.user_id, self.user.id)
        self.assertEqual(self.auth.get_current_user(session.token).id, self.user.id)

    def test_login_wrong_password_or_unknown_email_same_message(self):
        with self.assertRaises(AuthenticationError) as wrong_pwd:
            self.auth.login("lucas@email.com", "errada123")
        with self.assertRaises(AuthenticationError) as unknown:
            self.auth.login("ninguem@email.com", "senha1234")
        self.assertEqual(str(wrong_pwd.exception), str(unknown.exception))

    def test_login_validates_email(self):
        cases = {
            "": "Informe o e-mail.",
            "   ": "Informe o e-mail.",
            None: "Informe o e-mail.",
            "lucas": "E-mail inválido.",
            "lucas@email": "E-mail inválido.",
            "a" * 250 + "@x.com": "E-mail inválido.",
        }
        for email, message in cases.items():
            with self.subTest(email=email):
                with self.assertRaises(ValidationError) as ctx:
                    self.auth.login(email, "senha1234")
                self.assertEqual(str(ctx.exception), message)

    def test_login_validates_password(self):
        cases = {
            "": "Informe a senha.",
            None: "Informe a senha.",
            "x" * (PASSWORD_MAX_LENGTH + 1): (
                f"A senha deve ter no máximo {PASSWORD_MAX_LENGTH} caracteres."
            ),
        }
        for password, message in cases.items():
            with self.subTest(password=(password or "")[:10]):
                with self.assertRaises(ValidationError) as ctx:
                    self.auth.login("lucas@email.com", password)
                self.assertEqual(str(ctx.exception), message)

    def test_login_does_not_apply_strength_rules(self):
        # Senha fraca mas no formato válido: deve chegar à checagem de
        # credenciais (erro genérico), e não à regra de força do cadastro.
        with self.assertRaises(AuthenticationError):
            self.auth.login("lucas@email.com", "abc")

    def test_inactive_user_cannot_login(self):
        self.user.is_active = False
        with self.assertRaises(AuthenticationError):
            self.auth.login("lucas@email.com", "senha1234")

    def test_logout_invalidates_token(self):
        token = self.auth.login("lucas@email.com", "senha1234").token
        self.auth.logout(token)
        with self.assertRaises(AuthenticationError):
            self.auth.get_current_user(token)

    def test_session_expires(self):
        token = self.auth.login("lucas@email.com", "senha1234").token
        self.clock.current += timedelta(minutes=59)
        self.auth.get_current_user(token)  # ainda válida
        self.clock.current += timedelta(minutes=1)
        with self.assertRaises(AuthenticationError):
            self.auth.get_current_user(token)

    def test_invalid_token(self):
        with self.assertRaises(AuthenticationError):
            self.auth.get_current_user("token-falso")


if __name__ == "__main__":
    unittest.main()
