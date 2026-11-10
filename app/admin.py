"""
Administrative, Compliance & Fraud Operations Management Service.
Provides analyst controls, case management, manual transaction resolution,
blacklist maintenance, dynamic rule tuning, and forensic analytics.
"""
import json
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from app.db import Database


class AdminService:
    def __init__(self, db: Optional[Database] = None):
        self.db = db or Database()

    # -----------------------------------------------------------------
    # User & Wallet Controls
    # -----------------------------------------------------------------
    def list_all_users(self) -> List[Dict[str, Any]]:
        """List all users with their associated wallet status and balance."""
        return self.db.fetch_all(
            """
            SELECT 
                u.id AS user_id,
                u.username,
                u.role,
                u.full_name,
                u.email,
                u.is_locked,
                u.failed_logins,
                u.created_at,
                w.id AS wallet_id,
                w.wallet_number,
                w.balance,
                w.status AS wallet_status
            FROM users u
            LEFT JOIN wallets w ON w.user_id = u.id
            ORDER BY u.id ASC
            """
        )

    def lock_user(self, user_id: int, admin_id: Optional[int] = None, reason: str = "Admin security hold") -> Dict[str, Any]:
        """Lock user account."""
        self.db.execute("UPDATE users SET is_locked = 1 WHERE id = ?", (user_id,))
        self.db.execute(
            "INSERT INTO audit_logs (user_id, action, details) VALUES (?, 'USER_LOCKED', ?)",
            (admin_id, f"Locked user ID {user_id}. Reason: {reason}")
        )
        return {"success": True, "message": f"User {user_id} locked."}

    def unlock_user(self, user_id: int, admin_id: Optional[int] = None) -> Dict[str, Any]:
        """Unlock user account and reset failed login counter."""
        self.db.execute("UPDATE users SET is_locked = 0, failed_logins = 0 WHERE id = ?", (user_id,))
        self.db.execute(
            "INSERT INTO audit_logs (user_id, action, details) VALUES (?, 'USER_UNLOCKED', ?)",
            (admin_id, f"Unlocked user ID {user_id}")
        )
        return {"success": True, "message": f"User {user_id} unlocked."}

    def freeze_wallet(self, wallet_id: int, admin_id: Optional[int] = None, reason: str = "Fraud suspicion") -> Dict[str, Any]:
        """Freeze a wallet from executing outbound transactions."""
        self.db.execute("UPDATE wallets SET status = 'frozen' WHERE id = ?", (wallet_id,))
        self.db.execute(
            "INSERT INTO audit_logs (user_id, action, details) VALUES (?, 'WALLET_FROZEN', ?)",
            (admin_id, f"Frozen wallet ID {wallet_id}. Reason: {reason}")
        )
        return {"success": True, "message": f"Wallet {wallet_id} has been frozen."}

    def unfreeze_wallet(self, wallet_id: int, admin_id: Optional[int] = None) -> Dict[str, Any]:
        """Restore a wallet to active status."""
        self.db.execute("UPDATE wallets SET status = 'active' WHERE id = ?", (wallet_id,))
        self.db.execute(
            "INSERT INTO audit_logs (user_id, action, details) VALUES (?, 'WALLET_UNFROZEN', ?)",
            (admin_id, f"Restored wallet ID {wallet_id} to active")
        )
        return {"success": True, "message": f"Wallet {wallet_id} has been reactivated."}

    # -----------------------------------------------------------------
    # Fraud Alerts Case Management
    # -----------------------------------------------------------------
    def get_alerts(self, status_filter: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieve fraud alerts with contextual transaction and wallet details."""
        if status_filter:
            return self.db.fetch_all(
                """
                SELECT 
                    fa.*,
                    t.transaction_uuid,
                    t.amount,
                    t.status AS tx_status,
                    t.flagged_rules,
                    w.wallet_number,
                    u.username
                FROM fraud_alerts fa
                LEFT JOIN transactions t ON fa.transaction_id = t.id
                LEFT JOIN wallets w ON fa.wallet_id = w.id
                LEFT JOIN users u ON w.user_id = u.id
                WHERE fa.status = ?
                ORDER BY fa.created_at DESC
                LIMIT ?
                """,
                (status_filter, limit)
            )
        else:
            return self.db.fetch_all(
                """
                SELECT 
                    fa.*,
                    t.transaction_uuid,
                    t.amount,
                    t.status AS tx_status,
                    t.flagged_rules,
                    w.wallet_number,
                    u.username
                FROM fraud_alerts fa
                LEFT JOIN transactions t ON fa.transaction_id = t.id
                LEFT JOIN wallets w ON fa.wallet_id = w.id
                LEFT JOIN users u ON w.user_id = u.id
                ORDER BY fa.created_at DESC
                LIMIT ?
                """,
                (limit,)
            )

    def review_alert(
        self,
        alert_id: int,
        action: str,  # 'APPROVE_RELEASE', 'CONFIRM_FRAUD_BLOCK', 'DISMISS'
        notes: str,
        admin_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Analyst decision on a flagged or held transaction alert.
        """
        alert = self.db.fetch_one("SELECT * FROM fraud_alerts WHERE id = ?", (alert_id,))
        if not alert:
            return {"success": False, "message": "Alert not found."}

        tx_id = alert["transaction_id"]
        wallet_id = alert["wallet_id"]
        tx = self.db.fetch_one("SELECT * FROM transactions WHERE id = ?", (tx_id,)) if tx_id else None

        with self.db.transaction():
            now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            if action == "APPROVE_RELEASE":
                # If transaction was held under PENDING_REVIEW, release funds
                if tx and tx["status"] == "PENDING_REVIEW":
                    sender = self.db.fetch_one("SELECT * FROM wallets WHERE id = ?", (tx["sender_wallet_id"],))
                    receiver = self.db.fetch_one("SELECT * FROM wallets WHERE id = ?", (tx["receiver_wallet_id"],))
                    amount = tx["amount"]

                    if sender and receiver:
                        if sender["balance"] >= amount:
                            new_s_bal = round(sender["balance"] - amount, 2)
                            new_r_bal = round(receiver["balance"] + amount, 2)
                            self.db.execute("UPDATE wallets SET balance = ? WHERE id = ?", (new_s_bal, sender["id"]))
                            self.db.execute("UPDATE wallets SET balance = ? WHERE id = ?", (new_r_bal, receiver["id"]))
                            self.db.execute("UPDATE transactions SET status = 'COMPLETED' WHERE id = ?", (tx["id"],))
                        else:
                            return {"success": False, "message": "Cannot release: Sender no longer has sufficient balance."}

                self.db.execute(
                    """
                    UPDATE fraud_alerts 
                    SET status = 'DISMISSED', analyst_notes = ?, resolved_at = ?
                    WHERE id = ?
                    """,
                    (f"Analyst Approved & Released: {notes}", now_str, alert_id)
                )
                self.db.execute(
                    "INSERT INTO audit_logs (user_id, action, details) VALUES (?, 'ALERT_RELEASED', ?)",
                    (admin_id, f"Approved and released alert {alert_id} for tx {tx_id}")
                )
                return {"success": True, "message": "Transaction verified and approved. Funds released."}

            elif action == "CONFIRM_FRAUD_BLOCK":
                if tx:
                    self.db.execute("UPDATE transactions SET status = 'BLOCKED' WHERE id = ?", (tx["id"],))
                # Freeze sender wallet
                self.db.execute("UPDATE wallets SET status = 'frozen' WHERE id = ?", (wallet_id,))
                self.db.execute(
                    """
                    UPDATE fraud_alerts 
                    SET status = 'CONFIRMED_FRAUD', action_taken = 'WALLET_FROZEN', analyst_notes = ?, resolved_at = ?
                    WHERE id = ?
                    """,
                    (f"Confirmed Fraud: {notes}", now_str, alert_id)
                )
                self.db.execute(
                    "INSERT INTO audit_logs (user_id, action, details) VALUES (?, 'ALERT_CONFIRMED_FRAUD', ?)",
                    (admin_id, f"Confirmed fraud on alert {alert_id}. Wallet {wallet_id} frozen.")
                )
                return {"success": True, "message": "Fraud confirmed. Transaction blocked and wallet frozen."}

            else:  # DISMISS
                self.db.execute(
                    """
                    UPDATE fraud_alerts 
                    SET status = 'DISMISSED', analyst_notes = ?, resolved_at = ?
                    WHERE id = ?
                    """,
                    (f"Dismissed / False Positive: {notes}", now_str, alert_id)
                )
                self.db.execute(
                    "INSERT INTO audit_logs (user_id, action, details) VALUES (?, 'ALERT_DISMISSED', ?)",
                    (admin_id, f"Dismissed alert {alert_id}")
                )
                return {"success": True, "message": "Alert marked as dismissed."}

    # -----------------------------------------------------------------
    # Blacklist Management
    # -----------------------------------------------------------------
    def list_blacklist(self) -> List[Dict[str, Any]]:
        return self.db.fetch_all("SELECT * FROM blacklist ORDER BY created_at DESC")

    def add_to_blacklist(
        self,
        entity_type: str,
        entity_value: str,
        reason: str,
        added_by: str = "ADMIN"
    ) -> Dict[str, Any]:
        """Add an entity (WALLET, USER, IP, DEVICE) to blacklist."""
        entity_type = entity_type.upper().strip()
        entity_value = entity_value.strip()

        if entity_type not in ["WALLET", "USER", "IP", "DEVICE"]:
            return {"success": False, "message": "Invalid entity type. Must be WALLET, USER, IP, or DEVICE."}

        existing = self.db.fetch_one(
            "SELECT id FROM blacklist WHERE entity_type = ? AND LOWER(entity_value) = LOWER(?)",
            (entity_type, entity_value)
        )
        if existing:
            return {"success": False, "message": f"{entity_type} '{entity_value}' is already blacklisted."}

        self.db.execute(
            """
            INSERT INTO blacklist (entity_type, entity_value, reason, added_by)
            VALUES (?, ?, ?, ?)
            """,
            (entity_type, entity_value, reason, added_by)
        )
        return {"success": True, "message": f"Successfully added {entity_type} '{entity_value}' to blacklist."}

    def remove_from_blacklist(self, blacklist_id: int) -> Dict[str, Any]:
        self.db.execute("DELETE FROM blacklist WHERE id = ?", (blacklist_id,))
        return {"success": True, "message": "Entity removed from blacklist."}

    # -----------------------------------------------------------------
    # Rules Management
    # -----------------------------------------------------------------
    def get_rules(self) -> List[Dict[str, Any]]:
        return self.db.fetch_all("SELECT * FROM rules_config ORDER BY id ASC")

    def update_rule(
        self,
        rule_code: str,
        weight: Optional[float] = None,
        threshold: Optional[float] = None,
        is_enabled: Optional[int] = None,
        action: Optional[str] = None
    ) -> Dict[str, Any]:
        rule = self.db.fetch_one("SELECT * FROM rules_config WHERE rule_code = ?", (rule_code,))
        if not rule:
            return {"success": False, "message": f"Rule '{rule_code}' not found."}

        new_weight = weight if weight is not None else rule["weight"]
        new_thresh = threshold if threshold is not None else rule["threshold"]
        new_enabled = is_enabled if is_enabled is not None else rule["is_enabled"]
        new_action = action if action is not None else rule["action_if_triggered"]

        self.db.execute(
            """
            UPDATE rules_config 
            SET weight = ?, threshold = ?, is_enabled = ?, action_if_triggered = ?
            WHERE rule_code = ?
            """,
            (new_weight, new_thresh, new_enabled, new_action, rule_code)
        )
        return {"success": True, "message": f"Rule '{rule_code}' updated successfully."}

    # -----------------------------------------------------------------
    # Analytics Dashboard
    # -----------------------------------------------------------------
    def get_dashboard_metrics(self) -> Dict[str, Any]:
        """Aggregate statistical metrics for executive and analyst dashboards."""
        total_tx = self.db.fetch_one("SELECT COUNT(*) AS c, SUM(amount) AS v FROM transactions") or {"c": 0, "v": 0.0}
        approved_tx = self.db.fetch_one("SELECT COUNT(*) AS c FROM transactions WHERE status = 'COMPLETED'") or {"c": 0}
        review_tx = self.db.fetch_one("SELECT COUNT(*) AS c FROM transactions WHERE status = 'PENDING_REVIEW'") or {"c": 0}
        blocked_tx = self.db.fetch_one("SELECT COUNT(*) AS c FROM transactions WHERE status = 'BLOCKED'") or {"c": 0}
        open_alerts = self.db.fetch_one("SELECT COUNT(*) AS c FROM fraud_alerts WHERE status = 'OPEN'") or {"c": 0}

        count_total = total_tx["c"] or 0
        volume_total = total_tx["v"] or 0.0
        count_blocked = blocked_tx["c"] or 0
        count_review = review_tx["c"] or 0
        count_approved = approved_tx["c"] or 0
        fraud_rate = (100.0 * count_blocked / count_total) if count_total > 0 else 0.0

        top_rules = self.db.fetch_all(
            """
            SELECT alert_type, COUNT(*) AS occurrences, ROUND(AVG(risk_score), 1) AS avg_score
            FROM fraud_alerts
            GROUP BY alert_type
            ORDER BY occurrences DESC
            LIMIT 5
            """
        )

        recent_alerts = self.get_alerts(limit=5)

        return {
            "total_transactions": count_total,
            "total_volume": volume_total,
            "approved_count": count_approved,
            "review_count": count_review,
            "blocked_count": count_blocked,
            "fraud_rate_percent": round(fraud_rate, 2),
            "open_alerts_count": open_alerts["c"] or 0,
            "top_rules": top_rules,
            "recent_alerts": recent_alerts
        }

    # -----------------------------------------------------------------
    # Forensic Reports & Analytical Queries
    # -----------------------------------------------------------------
    def get_top_high_risk_wallets(self, limit: int = 15) -> List[Dict[str, Any]]:
        """Query top wallets by open/investigating fraud alerts."""
        return self.db.fetch_all(
            """
            SELECT 
                w.id AS wallet_id,
                w.wallet_number,
                u.username,
                u.email,
                w.balance,
                w.status AS wallet_status,
                COUNT(fa.id) AS alert_count,
                ROUND(AVG(fa.risk_score), 1) AS avg_risk_score,
                MAX(fa.risk_score) AS max_risk_score
            FROM wallets w
            JOIN users u ON w.user_id = u.id
            JOIN fraud_alerts fa ON fa.wallet_id = w.id
            WHERE fa.status IN ('OPEN', 'INVESTIGATING')
            GROUP BY w.id, w.wallet_number, u.username, u.email, w.balance, w.status
            ORDER BY alert_count DESC, max_risk_score DESC
            LIMIT ?
            """,
            (limit,)
        )

    def get_velocity_spikes(self, limit: int = 15) -> List[Dict[str, Any]]:
        """Query wallets with high frequency of transfers in recent window."""
        return self.db.fetch_all(
            """
            SELECT 
                t.sender_wallet_id,
                w.wallet_number,
                u.username,
                COUNT(*) AS tx_count,
                ROUND(SUM(t.amount), 2) AS total_amount,
                MAX(t.timestamp) AS last_tx_time
            FROM transactions t
            LEFT JOIN wallets w ON t.sender_wallet_id = w.id
            LEFT JOIN users u ON w.user_id = u.id
            WHERE t.transaction_type IN ('TRANSFER', 'WITHDRAWAL')
            GROUP BY t.sender_wallet_id, w.wallet_number, u.username
            HAVING tx_count >= 2
            ORDER BY tx_count DESC
            LIMIT ?
            """,
            (limit,)
        )

    def get_structuring_records(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Detect smurfing/structuring transactions between $9k and $10k."""
        return self.db.fetch_all(
            """
            SELECT 
                t.id,
                t.transaction_uuid,
                w.wallet_number AS sender_wallet,
                u.username,
                t.amount,
                t.risk_score,
                t.status,
                t.timestamp
            FROM transactions t
            JOIN wallets w ON t.sender_wallet_id = w.id
            JOIN users u ON w.user_id = u.id
            WHERE t.amount BETWEEN 9000.00 AND 9999.99
            ORDER BY t.timestamp DESC
            LIMIT ?
            """,
            (limit,)
        )

    def get_balance_drain_records(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Query transactions that drained majority of available balance."""
        return self.db.fetch_all(
            """
            SELECT 
                t.transaction_uuid,
                u.username,
                w.wallet_number,
                t.amount,
                w.balance AS current_balance,
                t.risk_score,
                t.status,
                t.timestamp
            FROM transactions t
            JOIN wallets w ON t.sender_wallet_id = w.id
            JOIN users u ON w.user_id = u.id
            WHERE t.risk_score >= 40.0
            ORDER BY t.timestamp DESC
            LIMIT ?
            """,
            (limit,)
        )

    def get_audit_trail(self, limit: int = 30) -> List[Dict[str, Any]]:
        """Retrieve recent administrative audit logs."""
        return self.db.fetch_all(
            """
            SELECT 
                al.id,
                COALESCE(u.username, 'SYSTEM') AS performed_by,
                al.action,
                al.details,
                al.ip_address,
                al.timestamp
            FROM audit_logs al
            LEFT JOIN users u ON al.user_id = u.id
            ORDER BY al.timestamp DESC
            LIMIT ?
            """,
            (limit,)
        )
