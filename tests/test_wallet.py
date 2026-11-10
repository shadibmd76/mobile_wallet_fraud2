"""
Unit tests for Wallet operations and transaction lifecycle.
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
from app.wallet import WalletService


class TestWalletService(unittest.TestCase):
    def setUp(self):
        self.temp_db_file = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_db_path = self.temp_db_file.name
        self.temp_db_file.close()

        Database._instance = None
        self.db = Database(db_path=self.temp_db_path)
        self.auth = AuthService(self.db)
        self.wallet = WalletService(self.db)

        # Create two test users
        u1 = self.auth.register("wallet_user_1", "Pass12345", "User One", "u1@test.com", initial_deposit=1000.0)
        u2 = self.auth.register("wallet_user_2", "Pass12345", "User Two", "u2@test.com", initial_deposit=200.0)
        self.w1_num = u1["wallet_number"]
        self.w2_num = u2["wallet_number"]
        self.w1 = self.wallet.get_wallet_by_number(self.w1_num)
        self.w2 = self.wallet.get_wallet_by_number(self.w2_num)

    def tearDown(self):
        self.db.close()
        try:
            os.remove(self.temp_db_path)
        except OSError:
            pass
        Database._instance = None

    def test_deposit(self):
        res = self.wallet.deposit(self.w1["id"], 250.0, "Test Top-up")
        self.assertTrue(res["success"])
        self.assertEqual(res["new_balance"], 1250.0)

    def test_transfer_success(self):
        res = self.wallet.transfer(
            sender_wallet_id=self.w1["id"],
            receiver_wallet_number=self.w2_num,
            amount=150.0,
            location={"city": "Boston", "country": "US", "lat": 42.3601, "lon": -71.0589, "ip": "10.0.0.1"}
        )
        self.assertTrue(res["success"])
        self.assertEqual(res["status"], "COMPLETED")

        updated_w1 = self.wallet.get_wallet_by_id(self.w1["id"])
        updated_w2 = self.wallet.get_wallet_by_id(self.w2["id"])
        self.assertEqual(updated_w1["balance"], 850.0)
        self.assertEqual(updated_w2["balance"], 350.0)

    def test_insufficient_funds_rejected(self):
        res = self.wallet.transfer(
            sender_wallet_id=self.w2["id"],  # has only $200
            receiver_wallet_number=self.w1_num,
            amount=999.0
        )
        self.assertFalse(res["success"])
        self.assertIn("insufficient", res["message"].lower())


if __name__ == "__main__":
    unittest.main()
