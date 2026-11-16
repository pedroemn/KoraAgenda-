import unittest

from app.container import Container
from app.core.exceptions import (
    AuthenticationError,
    ConflictError,
    NotFoundError,
    ValidationError,
)

VALID = {
    "name": "Lucas Silva",
    "email": "Lucas@Email.com",
    "phone": "(11) 98765-4321",
    "password": "senha1234",
}


class UserServiceTest(unittest.TestCase):
    def setUp(self):
        container = Container()
        self.users = container.user_service
        self.auth = container.auth_service

    def test_create_user_normalizes_data_and_hashes_password(self):
        user = self.users.create_user(**VALID)
        self.assertEqual(user.email, "lucas@email.com")
        self.assertEqual(user.phone, "11987654321")
        self.assertNotIn("senha1234", user.password_hash)
        self.assertNotIn("password_hash", user.to_public())

    def test_create_user_rejects_duplicate_email(self):
        self.users.create_user(**VALID)
        with self.assertRaises(ConflictError):
            self.users.create_user(**{**VALID, "email": "lucas@email.com"})

    def test_create_user_validates_fields(self):
        invalid_cases = [
            {"name": "L"},
            {"email": "sem-arroba"},
            {"phone": "123"},
            {"password": "curta1"},
            {"password": "somenteletras"},
        ]
        for override in invalid_cases:
            with self.subTest(override=override):
                with self.assertRaises(ValidationError):
                    self.users.create_user(**{**VALID, **override})

    def test_get_and_list_users(self):
        user = self.users.create_user(**VALID)
        self.assertIs(self.users.get_user(user.id), user)
        self.assertEqual(len(self.users.list_users()), 1)
        with self.assertRaises(NotFoundError):
            self.users.get_user("inexistente")

    def test_update_user(self):
        user = self.users.create_user(**VALID)
        updated = self.users.update_user(user.id, name="Lucas S.", phone="11 91234-5678")
        self.assertEqual(updated.name, "Lucas S.")
        self.assertEqual(updated.phone, "11912345678")
        self.assertEqual(updated.email, "lucas@email.com")

    def test_update_user_rejects_email_of_another_user(self):
        self.users.create_user(**VALID)
        other = self.users.create_user(**{**VALID, "email": "outro@email.com"})
        with self.assertRaises(ConflictError):
            self.users.update_user(other.id, email="lucas@email.com")

    def test_change_password_requires_current_and_revokes_sessions(self):
        user = self.users.create_user(**VALID)
        token = self.auth.login(VALID["email"], VALID["password"]).token

        with self.assertRaises(AuthenticationError):
            self.users.change_password(user.id, "errada123", "nova12345")

        self.users.change_password(user.id, VALID["password"], "nova12345")
        with self.assertRaises(AuthenticationError):
            self.auth.get_current_user(token)
        self.assertTrue(self.auth.login(VALID["email"], "nova12345").token)

    def test_delete_user_removes_user_and_sessions(self):
        user = self.users.create_user(**VALID)
        token = self.auth.login(VALID["email"], VALID["password"]).token

        self.users.delete_user(user.id)
        with self.assertRaises(NotFoundError):
            self.users.get_user(user.id)
        with self.assertRaises(AuthenticationError):
            self.auth.get_current_user(token)
        with self.assertRaises(NotFoundError):
            self.users.delete_user(user.id)


if __name__ == "__main__":
    unittest.main()
