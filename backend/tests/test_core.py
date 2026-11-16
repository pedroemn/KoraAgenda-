import unittest
from datetime import datetime, timedelta, timezone

from app.core.config import Settings
from app.core.exceptions import ValidationError
from app.core.security import Pbkdf2PasswordHasher, TokenGenerator
from app.models.session import Session
from app.models.user import User
from app.utils.validators import UserValidator


class PasswordHasherTest(unittest.TestCase):
    def setUp(self):
        self.hasher = Pbkdf2PasswordHasher(iterations=1_000)

    def test_hash_and_verify(self):
        stored = self.hasher.hash("senha1234")
        self.assertTrue(stored.startswith("pbkdf2_sha256$1000$"))
        self.assertTrue(self.hasher.verify("senha1234", stored))
        self.assertFalse(self.hasher.verify("outra1234", stored))

    def test_same_password_gets_different_salt(self):
        self.assertNotEqual(self.hasher.hash("senha1234"), self.hasher.hash("senha1234"))

    def test_malformed_hash_is_rejected(self):
        for stored in ["", "abc", "md5$1$00$00", "pbkdf2_sha256$x$zz$00"]:
            with self.subTest(stored=stored):
                self.assertFalse(self.hasher.verify("senha1234", stored))


class TokenGeneratorTest(unittest.TestCase):
    def test_tokens_are_unique(self):
        tokens = TokenGenerator()
        self.assertNotEqual(tokens.generate(), tokens.generate())


class UserValidatorTest(unittest.TestCase):
    def test_uses_injected_settings(self):
        validator = UserValidator(Settings(password_min_length=12))
        with self.assertRaises(ValidationError) as ctx:
            validator.new_password("senha12345")
        self.assertIn("12", str(ctx.exception))

    def test_normalizes_values(self):
        validator = UserValidator()
        self.assertEqual(validator.name("  Lucas   Silva "), "Lucas Silva")
        self.assertEqual(validator.email(" A@B.COM "), "a@b.com")
        self.assertEqual(validator.phone("+55 (11) 98765-4321"), "5511987654321")


class ModelsTest(unittest.TestCase):
    def test_user_update_profile_changes_only_given_fields(self):
        user = User("Lucas", "a@b.com", "11987654321", "hash")
        before = user.updated_at
        user.update_profile(name="Lucas S.")
        self.assertEqual((user.name, user.email), ("Lucas S.", "a@b.com"))
        self.assertGreaterEqual(user.updated_at, before)

    def test_session_open_sets_expiration(self):
        now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        session = Session.open("t", "u", now, timedelta(minutes=60))
        self.assertFalse(session.is_expired(now + timedelta(minutes=59)))
        self.assertTrue(session.is_expired(now + timedelta(minutes=60)))


if __name__ == "__main__":
    unittest.main()
