"""
Unit tests for Fraud Detection Rules and Anomaly Scoring Engine.
"""
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path

# Ensure app is in python path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.auth import AuthService
from app.db import Database
from app.fraud_engine import FraudEngine
from app.wallet import WalletService


class TestFraudEngine(unittest.TestCase):
    def setUp(self):
        self.temp_db_file = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_db_path = self.temp_db_file.name
        self.temp_db_file.close()

        Database._instance = None
        self.db = Database(db_path=self.temp_db_path)
        self.auth = AuthService(self.db)
        self.fraud = FraudEngine(self.db)
        self.wallet = WalletService(self.db, self.fraud)

        u_sender = self.auth.register("fraud_sender", "Pass12345", "Sender Victim", "sender@test.com", initial_deposit=12000.0)
        u_recv = self.auth.register("fraud_recv", "Pass12345", "Receiver Mule", "recv@test.com", initial_deposit=100.0)
        self.sender = self.wallet.get_wallet_by_id(u_sender["user_id"])
        self.recv = self.wallet.get_wallet_by_id(u_recv["user_id"])

    def tearDown(self):
        self.db.close()
        try:
            os.remove(self.temp_db_path)
        except OSError:
            pass
        Database._instance = None

    def test_blacklist_rule_triggers_block(self):
        # Blacklist receiver wallet
        self.db.execute(
            "INSERT INTO blacklist (entity_type, entity_value, reason) VALUES ('WALLET', ?, 'Stolen Mule')",
            (self.recv["wallet_number"],)
        )
        eval_res = self.fraud.evaluate_transaction(
            sender_wallet=self.sender,
            receiver_wallet=self.recv,
            amount=50.0
        )
        self.assertFalse(eval_res["approved"])
        self.assertEqual(eval_res["status"], "BLOCKED")
        self.assertEqual(eval_res["risk_score"], 100.0)
        rule_codes = [r["rule_code"] for r in eval_res["flagged_rules"]]
        self.assertIn("RULE_BLACKLIST", rule_codes)

    def test_structuring_rule(self):
        # Transaction of $9,800 should trigger AML structuring check
        eval_res = self.fraud.evaluate_transaction(
            sender_wallet=self.sender,
            receiver_wallet=self.recv,
            amount=9800.0
        )
        rule_codes = [r["rule_code"] for r in eval_res["flagged_rules"]]
        self.assertIn("RULE_STRUCTURING", rule_codes)
        self.assertGreaterEqual(eval_res["risk_score"], 50.0)

    def test_rapid_balance_drain(self):
        # Sender has 12,000, attempts to drain 90% (10,800)
        eval_res = self.fraud.evaluate_transaction(
            sender_wallet=self.sender,
            receiver_wallet=self.recv,
            amount=10800.0
        )
        rule_codes = [r["rule_code"] for r in eval_res["flagged_rules"]]
        self.assertIn("RULE_RAPID_DRAIN", rule_codes)

    def test_impossible_travel(self):
        # Step 1: Record a prior transaction from Los Angeles
        t_base = datetime.now() - timedelta(minutes=20)
        self.wallet.transfer(
            sender_wallet_id=self.sender["id"],
            receiver_wallet_number=self.recv["wallet_number"],
            amount=20.0,
            location={"city": "Los Angeles", "country": "US", "lat": 34.0522, "lon": -118.2437, "ip": "4.2.2.1"},
            tx_time=t_base
        )

        # Step 2: 20 minutes later from Sydney, Australia (12,000 km away!)
        t_now = datetime.now()
        eval_res = self.fraud.evaluate_transaction(
            sender_wallet=self.sender,
            receiver_wallet=self.recv,
            amount=150.0,
            location={"city": "Sydney", "country": "AU", "lat": -33.8688, "lon": 151.2093, "ip": "139.130.4.5"},
            tx_time=t_now
        )
        rule_codes = [r["rule_code"] for r in eval_res["flagged_rules"]]
        self.assertIn("RULE_IMPOSSIBLE_TRAVEL", rule_codes)
        self.assertEqual(eval_res["status"], "BLOCKED")


if __name__ == "__main__":
    unittest.main()
