"""
Wallet Management Service.
Handles deposits, withdrawals, peer-to-peer transfers, and transaction persistence with Fraud Engine integration.
"""
import json
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from app.config import Config
from app.db import Database
from app.fraud_engine import FraudEngine
from app.security import SecurityService


class WalletService:
    def __init__(self, db: Optional[Database] = None, fraud_engine: Optional[FraudEngine] = None):
        self.db = db or Database()
        self.fraud_engine = fraud_engine or FraudEngine(self.db)

    def get_wallet_by_id(self, wallet_id: int) -> Optional[Dict[str, Any]]:
        return self.db.fetch_one("SELECT * FROM wallets WHERE id = ?", (wallet_id,))

    def get_wallet_by_number(self, wallet_number: str) -> Optional[Dict[str, Any]]:
        return self.db.fetch_one("SELECT * FROM wallets WHERE wallet_number = ?", (wallet_number.strip(),))

    def get_wallet_by_user_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        return self.db.fetch_one("SELECT * FROM wallets WHERE user_id = ?", (user_id,))

    def deposit(
        self,
        wallet_id: int,
        amount: float,
        notes: str = "Deposit",
        location: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Deposit funds into a wallet."""
        if amount <= 0:
            return {"success": False, "message": "Deposit amount must be positive."}

        wallet = self.get_wallet_by_id(wallet_id)
        if not wallet:
            return {"success": False, "message": "Wallet not found."}
        if wallet["status"] == "frozen":
            return {"success": False, "message": "Wallet is frozen. Deposits are not permitted."}

        tx_uuid = SecurityService.generate_uuid()
        loc_json = json.dumps(location or {})

        with self.db.transaction():
            # Update balance
            new_balance = round(wallet["balance"] + amount, 2)
            self.db.execute(
                "UPDATE wallets SET balance = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (new_balance, wallet_id)
            )
            # Record transaction
            self.db.execute(
                """
                INSERT INTO transactions (
                    transaction_uuid, receiver_wallet_id, amount, transaction_type,
                    status, risk_score, risk_level, location, notes
                ) VALUES (?, ?, ?, 'DEPOSIT', 'COMPLETED', 0.0, 'LOW', ?, ?)
                """,
                (tx_uuid, wallet_id, amount, loc_json, notes)
            )

        return {
            "success": True,
            "message": f"Successfully deposited ${amount:,.2f}.",
            "new_balance": new_balance,
            "transaction_uuid": tx_uuid
        }

    def transfer(
        self,
        sender_wallet_id: int,
        receiver_wallet_number: str,
        amount: float,
        location: Optional[Dict[str, Any]] = None,
        device_fingerprint: Optional[str] = None,
        notes: str = "P2P Transfer",
        tx_time: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """
        Execute peer-to-peer transfer protected by the Real-time Fraud Detection Engine.
        """
        if amount <= 0:
            return {"success": False, "message": "Transfer amount must be greater than zero."}

        sender = self.get_wallet_by_id(sender_wallet_id)
        if not sender:
            return {"success": False, "message": "Sender wallet does not exist."}

        if sender["status"] == "frozen":
            return {"success": False, "message": "Transaction declined. Your wallet is currently frozen for security."}

        receiver = self.get_wallet_by_number(receiver_wallet_number)
        if not receiver:
            return {"success": False, "message": f"Destination wallet '{receiver_wallet_number}' was not found."}

        if sender["id"] == receiver["id"]:
            return {"success": False, "message": "Cannot transfer funds to the same wallet."}

        if sender["balance"] < amount:
            return {
                "success": False,
                "message": f"Insufficient funds. Balance: ${sender['balance']:,.2f}, Requested: ${amount:,.2f}"
            }

        # -------------------------------------------------------------
        # Fraud Engine Real-time Evaluation
        # -------------------------------------------------------------
        evaluation = self.fraud_engine.evaluate_transaction(
            sender_wallet=sender,
            receiver_wallet=receiver,
            amount=amount,
            tx_type="TRANSFER",
            location=location,
            device_fingerprint=device_fingerprint,
            tx_time=tx_time
        )

        tx_uuid = SecurityService.generate_uuid()
        status = evaluation["status"]
        risk_score = evaluation["risk_score"]
        risk_level = evaluation["risk_level"]
        flagged_rules = json.dumps(evaluation["flagged_rules"])
        loc_json = json.dumps(location or {})
        reasons_str = "; ".join(evaluation["reasons"]) or "Standard transaction"

        with self.db.transaction():
            # 1. Insert Transaction Record
            cur = self.db.execute(
                """
                INSERT INTO transactions (
                    transaction_uuid, sender_wallet_id, receiver_wallet_id, amount,
                    transaction_type, status, risk_score, risk_level, flagged_rules,
                    location, device_fingerprint, notes
                ) VALUES (?, ?, ?, ?, 'TRANSFER', ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    tx_uuid, sender["id"], receiver["id"], amount,
                    status, risk_score, risk_level, flagged_rules,
                    loc_json, device_fingerprint or "unknown-device", notes
                )
            )
            tx_id = cur.lastrowid

            # 2. Handle Status Cases
            if status == "COMPLETED":
                # Execute balance movement
                new_sender_bal = round(sender["balance"] - amount, 2)
                new_recv_bal = round(receiver["balance"] + amount, 2)

                self.db.execute("UPDATE wallets SET balance = ? WHERE id = ?", (new_sender_bal, sender["id"]))
                self.db.execute("UPDATE wallets SET balance = ? WHERE id = ?", (new_recv_bal, receiver["id"]))
                msg = f"Transfer of ${amount:,.2f} completed successfully."

            elif status == "PENDING_REVIEW":
                # Alert raised, funds held
                self.db.execute(
                    """
                    INSERT INTO fraud_alerts (
                        transaction_id, wallet_id, alert_type, risk_score, reasons, status, action_taken
                    ) VALUES (?, ?, 'TRANSACTION_HOLD', ?, ?, 'OPEN', 'FLAGGED')
                    """,
                    (tx_id, sender["id"], risk_score, reasons_str)
                )
                msg = (
                    f"Transfer held for security verification (Risk Score: {risk_score}/100). "
                    f"Reason: {reasons_str}"
                )

            else:  # BLOCKED
                action_taken = "WALLET_FROZEN" if evaluation.get("auto_freeze") else "BLOCKED"
                self.db.execute(
                    """
                    INSERT INTO fraud_alerts (
                        transaction_id, wallet_id, alert_type, risk_score, reasons, status, action_taken
                    ) VALUES (?, ?, 'HIGH_RISK_BLOCK', ?, ?, 'OPEN', ?)
                    """,
                    (tx_id, sender["id"], risk_score, reasons_str, action_taken)
                )
                if evaluation.get("auto_freeze"):
                    self.db.execute("UPDATE wallets SET status = 'frozen' WHERE id = ?", (sender["id"],))
                    msg = (
                        f"CRITICAL FRAUD ALERT: Transfer blocked and wallet automatically frozen "
                        f"(Risk Score: {risk_score}/100). Reason: {reasons_str}"
                    )
                else:
                    msg = (
                        f"Transfer blocked by fraud security engine (Risk Score: {risk_score}/100). "
                        f"Reason: {reasons_str}"
                    )

        return {
            "success": (status == "COMPLETED"),
            "status": status,
            "transaction_uuid": tx_uuid,
            "evaluation": evaluation,
            "message": msg
        }

    def withdraw(
        self,
        wallet_id: int,
        amount: float,
        location: Optional[Dict[str, Any]] = None,
        device_fingerprint: Optional[str] = None,
        notes: str = "ATM / Bank Cashout"
    ) -> Dict[str, Any]:
        """Withdrawal with fraud engine evaluation."""
        if amount <= 0:
            return {"success": False, "message": "Withdrawal amount must be greater than zero."}

        wallet = self.get_wallet_by_id(wallet_id)
        if not wallet:
            return {"success": False, "message": "Wallet not found."}

        if wallet["status"] == "frozen":
            return {"success": False, "message": "Wallet is frozen. Withdrawals are disabled."}

        if wallet["balance"] < amount:
            return {"success": False, "message": f"Insufficient funds. Balance: ${wallet['balance']:,.2f}"}

        evaluation = self.fraud_engine.evaluate_transaction(
            sender_wallet=wallet,
            receiver_wallet=None,
            amount=amount,
            tx_type="WITHDRAWAL",
            location=location,
            device_fingerprint=device_fingerprint
        )

        tx_uuid = SecurityService.generate_uuid()
        status = evaluation["status"]
        risk_score = evaluation["risk_score"]
        risk_level = evaluation["risk_level"]
        flagged_rules = json.dumps(evaluation["flagged_rules"])
        loc_json = json.dumps(location or {})
        reasons_str = "; ".join(evaluation["reasons"]) or "Standard withdrawal"

        with self.db.transaction():
            cur = self.db.execute(
                """
                INSERT INTO transactions (
                    transaction_uuid, sender_wallet_id, amount, transaction_type,
                    status, risk_score, risk_level, flagged_rules, location, device_fingerprint, notes
                ) VALUES (?, ?, ?, 'WITHDRAWAL', ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    tx_uuid, wallet["id"], amount, status, risk_score, risk_level,
                    flagged_rules, loc_json, device_fingerprint or "unknown-device", notes
                )
            )
            tx_id = cur.lastrowid

            if status == "COMPLETED":
                new_bal = round(wallet["balance"] - amount, 2)
                self.db.execute("UPDATE wallets SET balance = ? WHERE id = ?", (new_bal, wallet["id"]))
                msg = f"Withdrawal of ${amount:,.2f} completed successfully."
            else:
                self.db.execute(
                    """
                    INSERT INTO fraud_alerts (
                        transaction_id, wallet_id, alert_type, risk_score, reasons, status, action_taken
                    ) VALUES (?, ?, 'WITHDRAWAL_FRAUD', ?, ?, 'OPEN', 'BLOCKED')
                    """,
                    (tx_id, wallet["id"], risk_score, reasons_str)
                )
                msg = f"Withdrawal blocked due to high fraud risk score ({risk_score}/100)."

        return {
            "success": (status == "COMPLETED"),
            "status": status,
            "transaction_uuid": tx_uuid,
            "evaluation": evaluation,
            "message": msg
        }

    def get_transaction_history(self, wallet_id: int, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve recent transactions for a given wallet."""
        return self.db.fetch_all(
            """
            SELECT 
                t.*,
                sw.wallet_number AS sender_wallet,
                rw.wallet_number AS receiver_wallet
            FROM transactions t
            LEFT JOIN wallets sw ON t.sender_wallet_id = sw.id
            LEFT JOIN wallets rw ON t.receiver_wallet_id = rw.id
            WHERE t.sender_wallet_id = ? OR t.receiver_wallet_id = ?
            ORDER BY t.timestamp DESC
            LIMIT ?
            """,
            (wallet_id, wallet_id, limit)
        )
