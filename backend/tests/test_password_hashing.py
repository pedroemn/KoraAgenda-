"""Entrega 2 — Hash e autenticação segura."""

import hashlib
import hmac
import unittest
from unittest import mock

from app.container import Container
from app.core.exceptions import AuthenticationError
from app.core.security import (
    Argon2idPasswordHasher,
    Pbkdf2PasswordHasher,
    UpgradingPasswordHasher,
)

PASSWORD = "senha1234"


class Argon2idHasherTest(unittest.TestCase):
    def setUp(self):
        self.hasher = Argon2idPasswordHasher()

    def test_hash_is_phc_with_owasp_parameters(self):
        stored = self.hasher.hash(PASSWORD)
        parts = stored.split("$")
        self.assertEqual(parts[1:4], ["argon2id", "v=19", "m=19456,t=2,p=1"])
        self.assertNotIn(PASSWORD, stored)

    def test_salt_is_stored_and_random(self):
        first, second = self.hasher.hash(PASSWORD), self.hasher.hash(PASSWORD)
        self.assertNotEqual(first, second)                         # hashes diferentes
        self.assertNotEqual(first.split("$")[4], second.split("$")[4])  # salts diferentes
        self.assertTrue(self.hasher.verify(PASSWORD, first))
        self.assertTrue(self.hasher.verify(PASSWORD, second))

    def test_correct_and_incorrect_password(self):
        stored = self.hasher.hash(PASSWORD)
        self.assertTrue(self.hasher.verify(PASSWORD, stored))
        for wrong in ["senha1235", "Senha1234", "senha1234 ", "", "senha123"]:
            with self.subTest(wrong=wrong):
                self.assertFalse(self.hasher.verify(wrong, stored))

    def test_unicode_password(self):
        stored = self.hasher.hash("çãõ-ñ-日本-🔐-1")
        self.assertTrue(self.hasher.verify("çãõ-ñ-日本-🔐-1", stored))
        self.assertFalse(self.hasher.verify("cao-n-日本-🔐-1", stored))

    def test_tampered_or_malformed_hash_is_rejected(self):
        stored = self.hasher.hash(PASSWORD)
        tampered = stored[:-2] + ("AA" if not stored.endswith("AA") else "BB")
        cases = [
            tampered,
            stored.replace("argon2id", "argon2i"),
            stored.replace("v=19", "v=16"),
            "",
            "$argon2id$v=19$m=x,t=2,p=1$AAAA$AAAA",
            "$argon2id$v=19$t=2,p=1$AAAA$AAAA",
            "texto-puro",
        ]
        for value in cases:
            with self.subTest(value=value):
                self.assertFalse(self.hasher.verify(PASSWORD, value))

    def test_uses_constant_time_comparison_from_library(self):
        stored = self.hasher.hash(PASSWORD)
        with mock.patch("hmac.compare_digest", wraps=hmac.compare_digest) as spy:
            self.assertTrue(self.hasher.verify(PASSWORD, stored))
            self.assertFalse(self.hasher.verify("errada123", stored))
        self.assertEqual(spy.call_count, 2)

    def test_needs_rehash_when_parameters_change(self):
        stored = self.hasher.hash(PASSWORD)
        self.assertFalse(self.hasher.needs_rehash(stored))
        stronger = Argon2idPasswordHasher(memory_kib=47_104, iterations=1)
        self.assertTrue(stronger.needs_rehash(stored))
        # Hash antigo continua válido mesmo com a configuração nova.
        self.assertTrue(stronger.verify(PASSWORD, stored))


class UpgradingHasherTest(unittest.TestCase):
    def setUp(self):
        self.legacy = Pbkdf2PasswordHasher(iterations=1_000)
        self.hasher = UpgradingPasswordHasher(
            Argon2idPasswordHasher(), legacy=[Pbkdf2PasswordHasher(iterations=600_000)]
        )

    def test_new_hashes_use_argon2id(self):
        self.assertTrue(self.hasher.hash(PASSWORD).startswith("$argon2id$"))

    def test_legacy_pbkdf2_hash_still_verifies_and_needs_rehash(self):
        old = self.legacy.hash(PASSWORD)
        self.assertTrue(self.hasher.verify(PASSWORD, old))
        self.assertFalse(self.hasher.verify("errada123", old))
        self.assertTrue(self.hasher.needs_rehash(old))
        self.assertFalse(self.hasher.needs_rehash(self.hasher.hash(PASSWORD)))

    def test_unknown_format_is_rejected(self):
        plain_sha256 = hashlib.sha256(PASSWORD.encode()).hexdigest()
        self.assertFalse(self.hasher.verify(PASSWORD, plain_sha256))
        self.assertFalse(self.hasher.verify(PASSWORD, PASSWORD))


class SecureRegistrationAndLoginTest(unittest.TestCase):
    def setUp(self):
        self.container = Container()
        self.users = self.container.user_service
        self.auth = self.container.auth_service
        self.user = self.users.create_user(
            "Lucas Silva", "lucas@email.com", "11987654321", PASSWORD
        )

    def test_stored_record_has_no_plaintext_password(self):
        record = vars(self.container.users.get_by_id(self.user.id))
        self.assertTrue(record["password_hash"].startswith("$argon2id$"))
        for value in record.values():
            self.assertNotIn(PASSWORD, str(value))

    def test_login_correct(self):
        session = self.auth.login("lucas@email.com", PASSWORD)
        self.assertEqual(self.auth.get_current_user(session.token).id, self.user.id)

    def test_login_incorrect(self):
        for email, password in [
            ("lucas@email.com", "senha12345"),
            ("lucas@email.com", "SENHA1234"),
            ("naoexiste@email.com", PASSWORD),
        ]:
            with self.subTest(email=email, password=password):
                with self.assertRaises(AuthenticationError) as ctx:
                    self.auth.login(email, password)
                self.assertEqual(str(ctx.exception), "E-mail ou senha inválidos.")

    def test_unknown_email_still_computes_a_hash(self):
        # Mesmo custo de uma senha errada: não dá para descobrir e-mails pelo tempo.
        hasher = self.container.password_hasher
        with mock.patch.object(hasher, "verify", wraps=hasher.verify) as spy:
            with self.assertRaises(AuthenticationError):
                self.auth.login("naoexiste@email.com", PASSWORD)
        spy.assert_called_once()

    def test_legacy_hash_is_migrated_on_successful_login(self):
        self.user.password_hash = Pbkdf2PasswordHasher(iterations=1_000).hash(PASSWORD)

        with self.assertRaises(AuthenticationError):
            self.auth.login("lucas@email.com", "errada123")
        self.assertTrue(self.user.password_hash.startswith("pbkdf2_sha256$"))  # não migra

        self.auth.login("lucas@email.com", PASSWORD)
        self.assertTrue(self.user.password_hash.startswith("$argon2id$"))     # migrou
        self.auth.login("lucas@email.com", PASSWORD)                          # segue válido


if __name__ == "__main__":
    unittest.main()
