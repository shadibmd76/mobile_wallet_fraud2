"""
Authentication & Identity Management Service.
Handles user registration, login, password security, role validation, and lockout policies.
"""
from typing import Any, Dict, Optional, Tuple

from app.config import Config
from app.db import Database
from app.security import SecurityService


class AuthService:
    def __init__(self, db: Optional[Database] = None):
        self.db = db or Database()

    def register(
        self,
        username: str,
        password: str,
        full_name: str,
        email: str,
        phone: str = "",
        role: str = "user",
        initial_deposit: float = 1000.0,
        device_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Register a new user and automatically assign a provisioned digital wallet."""
        username = username.strip()
        email = email.strip().lower()

        if len(username) < 3:
            return {"success": False, "message": "Username must be at least 3 characters long."}
        if len(password) < 6:
            return {"success": False, "message": "Password must be at least 6 characters long."}

        # Check uniqueness
        if self.db.fetch_one("SELECT id FROM users WHERE LOWER(username) = LOWER(?)", (username,)):
            return {"success": False, "message": f"Username '{username}' is already registered."}

        if self.db.fetch_one("SELECT id FROM users WHERE LOWER(email) = LOWER(?)", (email,)):
            return {"success": False, "message": f"Email '{email}' is already registered."}

        pwd_hash, salt = SecurityService.hash_password(password)
        wallet_number = SecurityService.generate_wallet_number()

        with self.db.transaction():
            # 1. Create User
            cur = self.db.execute(
                """
                INSERT INTO users (username, password_hash, salt, role, full_name, email, phone, device_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (username, pwd_hash, salt, role, full_name, email, phone, device_id or f"dev-{username}")
            )
            user_id = cur.lastrowid

            # 2. Provision Wallet
            w_cur = self.db.execute(
                """
                INSERT INTO wallets (user_id, wallet_number, balance, currency, status)
                VALUES (?, ?, ?, 'USD', 'active')
                """,
                (user_id, wallet_number, initial_deposit)
            )
            wallet_id = w_cur.lastrowid

            # 3. Initial Deposit Transaction
            if initial_deposit > 0:
                tx_uuid = SecurityService.generate_uuid()
                self.db.execute(
                    """
                    INSERT INTO transactions (
                        transaction_uuid, receiver_wallet_id, amount, transaction_type,
                        status, risk_score, risk_level, notes
                    ) VALUES (?, ?, ?, 'DEPOSIT', 'COMPLETED', 0.0, 'LOW', 'Account Opening Welcome Credit')
                    """,
                    (tx_uuid, wallet_id, initial_deposit)
                )

            # 4. Audit Log
            self.db.execute(
                """
                INSERT INTO audit_logs (user_id, action, details)
                VALUES (?, 'USER_REGISTERED', ?)
                """,
                (user_id, f"User {username} registered with wallet {wallet_number}")
            )

        return {
            "success": True,
            "message": f"User '{username}' registered successfully.",
            "user_id": user_id,
            "wallet_number": wallet_number,
            "initial_balance": initial_deposit
        }

    def login(
        self,
        username: str,
        password: str,
        ip_address: str = "127.0.0.1",
        device_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Authenticate user credentials and enforce lockout policies."""
        username = username.strip()
        user = self.db.fetch_one("SELECT * FROM users WHERE LOWER(username) = LOWER(?)", (username,))

        if not user:
            return {"success": False, "message": "Invalid username or password."}

        # Check if account is locked
        if user["is_locked"]:
            return {
                "success": False,
                "message": "Account is locked due to multiple failed login attempts. Contact an administrator."
            }

        # Verify password
        is_valid = SecurityService.verify_password(password, user["password_hash"], user["salt"])

        if not is_valid:
            # Increment failed attempts
            failed = user["failed_logins"] + 1
            is_locked = 1 if failed >= Config.MAX_FAILED_LOGINS else 0
            self.db.execute(
                "UPDATE users SET failed_logins = ?, is_locked = ? WHERE id = ?",
                (failed, is_locked, user["id"])
            )
            self.db.execute(
                "INSERT INTO audit_logs (user_id, action, details, ip_address) VALUES (?, 'LOGIN_FAILED', ?, ?)",
                (user["id"], f"Failed password attempt ({failed}/{Config.MAX_FAILED_LOGINS})", ip_address)
            )

            if is_locked:
                return {
                    "success": False,
                    "message": "Too many failed attempts. Your account has been temporarily locked for security."
                }
            return {
                "success": False,
                "message": f"Invalid password. Remaining attempts before lockout: {Config.MAX_FAILED_LOGINS - failed}."
            }

        # Login Successful: Reset failed counter
        self.db.execute(
            "UPDATE users SET failed_logins = 0 WHERE id = ?",
            (user["id"],)
        )
        self.db.execute(
            "INSERT INTO audit_logs (user_id, action, details, ip_address) VALUES (?, 'LOGIN_SUCCESS', 'User logged in', ?)",
            (user["id"], ip_address)
        )

        # Retrieve wallet
        wallet = self.db.fetch_one("SELECT * FROM wallets WHERE user_id = ?", (user["id"],))

        return {
            "success": True,
            "message": "Login successful.",
            "user": user,
            "wallet": wallet
        }

    def get_user_by_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        return self.db.fetch_one("SELECT id, username, role, full_name, email, phone, is_locked FROM users WHERE id = ?", (user_id,))
