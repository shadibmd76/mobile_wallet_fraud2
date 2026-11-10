"""
Synthetic Transaction & Fraud Attack Simulator.
Generates realistic normal mobile wallet activity and specialized fraud attack patterns
to test and demonstrate the real-time Fraud Engine.
"""
import random
import time
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional

from app.db import Database
from app.fraud_engine import FraudEngine
from app.wallet import WalletService


class FraudSimulator:
    def __init__(self, db: Optional[Database] = None):
        self.db = db or Database()
        self.wallet_service = WalletService(self.db)
        self.engine = FraudEngine(self.db)

    # -----------------------------------------------------------------
    # Helper to find wallets
    # -----------------------------------------------------------------
    def _get_wallet_for_user(self, username: str) -> Optional[Dict[str, Any]]:
        return self.db.fetch_one(
            "SELECT w.* FROM wallets w JOIN users u ON w.user_id = u.id WHERE u.username = ?",
            (username,)
        )

    # -----------------------------------------------------------------
    # Scenario 1: Normal Everyday Transactions
    # -----------------------------------------------------------------
    def run_normal_transaction(self) -> Dict[str, Any]:
        """Simulate a completely normal peer-to-peer transfer between legitimate users."""
        users = ["alice", "bob", "charlie"]
        sender_name, recv_name = random.sample(users, 2)
        sender_w = self._get_wallet_for_user(sender_name)
        recv_w = self._get_wallet_for_user(recv_name)

        if not sender_w or not recv_w:
            return {"scenario": "Normal Transaction", "status": "FAILED", "reason": "Users not found"}

        # If sender balance is low, deposit starter funds
        if sender_w["balance"] < 100:
            self.wallet_service.deposit(sender_w["id"], 500.0, "Automatic Top-up")
            sender_w = self.wallet_service.get_wallet_by_id(sender_w["id"])

        amount = round(random.uniform(15.0, 85.0), 2)
        location = {
            "city": "New York",
            "country": "US",
            "lat": 40.7128,
            "lon": -74.0060,
            "ip": "24.120.55.101"
        }
        res = self.wallet_service.transfer(
            sender_wallet_id=sender_w["id"],
            receiver_wallet_number=recv_w["wallet_number"],
            amount=amount,
            location=location,
            device_fingerprint=f"dev-{sender_name}-trusted-01",
            notes=f"Normal P2P lunch split from {sender_name} to {recv_name}"
        )
        return {
            "scenario": "Normal Everyday Transfer",
            "sender": sender_name,
            "receiver": recv_name,
            "amount": amount,
            "result": res
        }

    # -----------------------------------------------------------------
    # Scenario 2: Account Takeover (ATO) & Sudden Balance Drain
    # -----------------------------------------------------------------
    def run_account_takeover_attack(self) -> Dict[str, Any]:
        """
        Simulate an Account Takeover where attacker drains 92% of the victim's
        funds from an unrecognized device during late off-hours.
        """
        victim_w = self._get_wallet_for_user("alice")
        mule_w = self._get_wallet_for_user("bob")

        if not victim_w or not mule_w:
            return {"scenario": "Account Takeover", "status": "FAILED", "reason": "Required users not found"}

        # Ensure victim has funds
        if victim_w["balance"] < 500:
            self.wallet_service.deposit(victim_w["id"], 2000.0, "Salary Deposit")
            victim_w = self.wallet_service.get_wallet_by_id(victim_w["id"])

        # Drain 92% of balance
        amount = round(victim_w["balance"] * 0.92, 2)
        
        # Off-hours timestamp (03:15 AM)
        off_hours_time = datetime.now().replace(hour=3, minute=15, second=0)

        location = {
            "city": "Unknown Region",
            "country": "RU",
            "lat": 55.7558,
            "lon": 37.6173,
            "ip": "185.220.101.5"
        }

        res = self.wallet_service.transfer(
            sender_wallet_id=victim_w["id"],
            receiver_wallet_number=mule_w["wallet_number"],
            amount=amount,
            location=location,
            device_fingerprint="rogue-jailbroken-iphone-x",
            notes="EMERGENCY FAST WITHDRAWAL",
            tx_time=off_hours_time
        )

        return {
            "scenario": "Account Takeover (ATO) & Rapid Drain",
            "sender": "alice",
            "receiver": "bob (external)",
            "amount": amount,
            "result": res
        }

    # -----------------------------------------------------------------
    # Scenario 3: High-Frequency Velocity Burst Attack
    # -----------------------------------------------------------------
    def run_velocity_burst_attack(self, burst_count: int = 5) -> List[Dict[str, Any]]:
        """Simulate a scripted bot spamming multiple transfers in rapid succession within seconds."""
        sender_w = self._get_wallet_for_user("bob")
        recv_w = self._get_wallet_for_user("charlie")

        if not sender_w or not recv_w:
            return [{"scenario": "Velocity Burst", "status": "FAILED"}]

        if sender_w["balance"] < (burst_count * 50):
            self.wallet_service.deposit(sender_w["id"], 1000.0, "Balance Seed")

        results = []
        for i in range(1, burst_count + 1):
            res = self.wallet_service.transfer(
                sender_wallet_id=sender_w["id"],
                receiver_wallet_number=recv_w["wallet_number"],
                amount=25.0,
                location={"city": "Chicago", "country": "US", "lat": 41.8781, "lon": -87.6298, "ip": "72.14.201.2"},
                device_fingerprint="dev-bob-android-12",
                notes=f"Velocity burst transfer #{i}"
            )
            results.append({
                "iteration": i,
                "amount": 25.0,
                "status": res["status"],
                "risk_score": res["evaluation"]["risk_score"],
                "message": res["message"]
            })

        return results

    # -----------------------------------------------------------------
    # Scenario 4: Card / Account Testing Micro-Transactions
    # -----------------------------------------------------------------
    def run_micro_transaction_probing(self, count: int = 4) -> List[Dict[str, Any]]:
        """Simulate an attacker checking if a stolen account is live using tiny transfers."""
        sender_w = self._get_wallet_for_user("charlie")
        recv_w = self._get_wallet_for_user("alice")

        results = []
        for i in range(1, count + 1):
            micro_amt = round(random.uniform(0.75, 2.50), 2)
            res = self.wallet_service.transfer(
                sender_wallet_id=sender_w["id"],
                receiver_wallet_number=recv_w["wallet_number"],
                amount=micro_amt,
                location={"city": "Miami", "country": "US", "lat": 25.7617, "lon": -80.1918, "ip": "104.28.19.11"},
                device_fingerprint="probing-bot-v1",
                notes=f"Micro test auth #{i}"
            )
            results.append({
                "iteration": i,
                "amount": micro_amt,
                "status": res["status"],
                "risk_score": res["evaluation"]["risk_score"],
                "message": res["message"]
            })

        return results

    # -----------------------------------------------------------------
    # Scenario 5: Impossible Travel (Geo-Velocity Anomaly)
    # -----------------------------------------------------------------
    def run_impossible_travel_attack(self) -> Dict[str, Any]:
        """
        Simulate a user initiating a transaction in New York, and 10 minutes later
        a transaction from Tokyo or London is attempted on the same account.
        """
        user_w = self._get_wallet_for_user("charlie")
        recv_w = self._get_wallet_for_user("bob")

        if not user_w or not recv_w:
            return {"scenario": "Impossible Travel", "status": "FAILED"}

        # Step 1: Base transaction in New York, USA
        t_base = datetime.now() - timedelta(minutes=15)
        self.wallet_service.transfer(
            sender_wallet_id=user_w["id"],
            receiver_wallet_number=recv_w["wallet_number"],
            amount=30.0,
            location={"city": "New York", "country": "US", "lat": 40.7128, "lon": -74.0060, "ip": "66.102.0.1"},
            device_fingerprint="charlie-macbook-home",
            notes="Morning coffee in NYC",
            tx_time=t_base
        )

        # Step 2: 15 minutes later in London, UK (5,570 km distance!)
        # Required speed: > 22,000 km/h
        t_london = datetime.now()
        res = self.wallet_service.transfer(
            sender_wallet_id=user_w["id"],
            receiver_wallet_number=recv_w["wallet_number"],
            amount=450.0,
            location={"city": "London", "country": "GB", "lat": 51.5074, "lon": -0.1278, "ip": "82.165.197.1"},
            device_fingerprint="foreign-suspicious-pc",
            notes="High-speed transfer from London",
            tx_time=t_london
        )

        return {
            "scenario": "Impossible Travel (NYC -> London in 15 mins)",
            "origin": "New York, USA (lat 40.71, lon -74.00)",
            "destination": "London, UK (lat 51.50, lon -0.12)",
            "time_difference": "15 minutes",
            "result": res
        }

    # -----------------------------------------------------------------
    # Scenario 6: Structuring / Smurfing (Anti-Money Laundering)
    # -----------------------------------------------------------------
    def run_structuring_attack(self) -> Dict[str, Any]:
        """
        Simulate money laundering structuring: transferring $9,850.00 to stay
        just beneath the regulatory $10,000 currency reporting limit.
        """
        sender_w = self._get_wallet_for_user("charlie")
        recv_w = self._get_wallet_for_user("bob")

        if not sender_w or not recv_w:
            return {"scenario": "Structuring", "status": "FAILED"}

        if sender_w["balance"] < 10000:
            self.wallet_service.deposit(sender_w["id"], 15000.0, "Commercial Wire")
            sender_w = self.wallet_service.get_wallet_by_id(sender_w["id"])

        smurf_amount = 9850.00
        res = self.wallet_service.transfer(
            sender_wallet_id=sender_w["id"],
            receiver_wallet_number=recv_w["wallet_number"],
            amount=smurf_amount,
            location={"city": "Dallas", "country": "US", "lat": 32.7767, "lon": -96.7970, "ip": "99.100.22.4"},
            device_fingerprint="dev-charlie-mac-01",
            notes="Contractor payment installment"
        )

        return {
            "scenario": "AML Structuring / Smurfing ($9,850.00)",
            "amount": smurf_amount,
            "result": res
        }

    # -----------------------------------------------------------------
    # Scenario 7: Blacklist Hit
    # -----------------------------------------------------------------
    def run_blacklist_attack(self) -> Dict[str, Any]:
        """Attempt to transfer funds to a known blacklisted mule wallet."""
        sender_w = self._get_wallet_for_user("alice")
        if not sender_w:
            return {"scenario": "Blacklist Hit", "status": "FAILED"}

        res = self.wallet_service.transfer(
            sender_wallet_id=sender_w["id"],
            receiver_wallet_number="MW-9999999999",  # Blacklisted mule account
            amount=150.0,
            location={"city": "San Francisco", "country": "US", "lat": 37.7749, "lon": -122.4194, "ip": "198.51.100.23"},
            device_fingerprint="dev-alice-ios-15",
            notes="Transfer to flagged mule recipient"
        )

        return {
            "scenario": "Blacklist Hit (Target: MW-9999999999)",
            "result": res
        }

    # -----------------------------------------------------------------
    # Batch Generator
    # -----------------------------------------------------------------
    def run_batch_simulation(
        self,
        total_transactions: int = 15,
        fraud_ratio: float = 0.4,
        callback: Optional[Callable[[int, int, Dict[str, Any]], None]] = None
    ) -> List[Dict[str, Any]]:
        """
        Execute an automated mixed batch of normal and fraudulent transactions.
        """
        logs = []
        for i in range(1, total_transactions + 1):
            is_fraud = (random.random() < fraud_ratio)
            if is_fraud:
                scenario_choice = random.choice([
                    self.run_account_takeover_attack,
                    self.run_impossible_travel_attack,
                    self.run_structuring_attack,
                    self.run_blacklist_attack
                ])
                entry = scenario_choice()
            else:
                entry = self.run_normal_transaction()

            logs.append(entry)
            if callback:
                callback(i, total_transactions, entry)
            time.sleep(0.05)  # slight realistic pause

        return logs
