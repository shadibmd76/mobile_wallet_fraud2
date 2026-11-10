"""
Unit tests for Authentication, Identity, and Cryptography.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

# Ensure app is in python path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.auth import AuthService
from app.db import Database
from app.security import SecurityService


class TestAuthService(unittest.TestCase):
    def setUp(self):
        # Create temp sqlite db for test isolation
        self.temp_db_file = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_db_path = self.temp_db_file.name
        self.temp_db_file.close()

        # Re-initialize Database singleton pointing to temp db
        Database._instance = None
        self.db = Database(db_path=self.temp_db_path)
        self.auth = AuthService(self.db)

    def tearDown(self):
        self.db.close()
        try:
            os.remove(self.temp_db_path)
        except OSError:
            pass
        Database._instance = None

    def test_password_hashing_and_verification(self):
        pwd = "SecurePassword@2026"
        pwd_hash, salt = SecurityService.hash_password(pwd)
        self.assertTrue(SecurityService.verify_password(pwd, pwd_hash, salt))
        self.assertFalse(SecurityService.verify_password("WrongPassword", pwd_hash, salt))

    def test_user_registration(self):
        res = self.auth.register(
            username="testuser",
            password="TestPassword123",
            full_name="Test Tester",
            email="testuser@example.com",
            initial_deposit=500.0
        )
        self.assertTrue(res["success"])
        self.assertTrue(res["wallet_number"].startswith("MW-"))
        self.assertEqual(res["initial_balance"], 500.0)

        # Duplicate username should fail
        dup = self.auth.register(
            username="testuser",
            password="AnotherPassword123",
            full_name="Duplicate User",
            email="another@example.com"
        )
        self.assertFalse(dup["success"])

    def test_login_success_and_failure_lockout(self):
        self.auth.register(
            username="lockout_user",
            password="ValidPass123",
            full_name="Lockout Target",
            email="lockout@example.com"
        )

        # Correct login
        login_ok = self.auth.login("lockout_user", "ValidPass123")
        self.assertTrue(login_ok["success"])
        self.assertIsNotNone(login_ok["wallet"])

        # Multiple failed attempts
        for _ in range(5):
            self.auth.login("lockout_user", "WrongPass")

        # Now account must be locked
        locked_attempt = self.auth.login("lockout_user", "ValidPass123")
        self.assertFalse(locked_attempt["success"])
        self.assertIn("locked", locked_attempt["message"].lower())


if __name__ == "__main__":
    unittest.main()
