"""
Database connection, migrations, query execution, and seed data initialization.
Supports both SQLite (default) and MySQL backends.
"""
import json
import os
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from app.config import Config
from app.security import SecurityService

class Database:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(Database, cls).__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self, db_path: Optional[str] = None):
        if self._initialized:
            return
        self.db_type = Config.DB_TYPE
        self.sqlite_path = db_path or Config.SQLITE_PATH
        self._local = threading.local()
        self.initialize_schema()
        self.seed_defaults()
        self._initialized = True

    def get_connection(self):
        """Thread-safe connection retrieval."""
        if self.db_type == "sqlite":
            if not hasattr(self._local, "conn") or self._local.conn is None:
                conn = sqlite3.connect(
                    self.sqlite_path, 
                    check_same_thread=False,
                    detect_types=sqlite3.PARSE_DECLTYPES
                )
                conn.row_factory = sqlite3.Row
                conn.execute("PRAGMA foreign_keys = ON;")
                self._local.conn = conn
            return self._local.conn
        elif self.db_type == "mysql":
            try:
                import mysql.connector # type: ignore
                if not hasattr(self._local, "conn") or self._local.conn is None or not self._local.conn.is_connected():
                    self._local.conn = mysql.connector.connect(
                        host=Config.MYSQL_HOST,
                        port=Config.MYSQL_PORT,
                        user=Config.MYSQL_USER,
                        password=Config.MYSQL_PASSWORD,
                        database=Config.MYSQL_DATABASE,
                        autocommit=False
                    )
                return self._local.conn
            except ImportError:
                raise RuntimeError("mysql-connector-python is not installed. Use SQLite or install package.")
        else:
            raise ValueError(f"Unsupported database type: {self.db_type}")

    def close(self):
        """Close current thread connection."""
        if hasattr(self._local, "conn") and self._local.conn:
            self._local.conn.close()
            self._local.conn = None

    @contextmanager
    def transaction(self):
        """Transaction context manager with automatic rollback on error."""
        conn = self.get_connection()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    def execute(self, query: str, params: Tuple = ()) -> sqlite3.Cursor:
        """Execute non-fetching query (INSERT, UPDATE, DELETE)."""
        conn = self.get_connection()
        # Adapt placeholders if MySQL (%s) vs SQLite (?)
        if self.db_type == "mysql":
            query = query.replace("?", "%s")
        cursor = conn.cursor()
        cursor.execute(query, params)
        conn.commit()
        return cursor

    def fetch_one(self, query: str, params: Tuple = ()) -> Optional[Dict[str, Any]]:
        """Fetch single row as dictionary."""
        conn = self.get_connection()
        if self.db_type == "mysql":
            query = query.replace("?", "%s")
            cursor = conn.cursor(dictionary=True)
            cursor.execute(query, params)
            row = cursor.fetchone()
            cursor.close()
            return row
        else:
            cursor = conn.cursor()
            cursor.execute(query, params)
            row = cursor.fetchone()
            if row is None:
                return None
            return dict(row)

    def fetch_all(self, query: str, params: Tuple = ()) -> List[Dict[str, Any]]:
        """Fetch all matching rows as list of dictionaries."""
        conn = self.get_connection()
        if self.db_type == "mysql":
            query = query.replace("?", "%s")
            cursor = conn.cursor(dictionary=True)
            cursor.execute(query, params)
            rows = cursor.fetchall()
            cursor.close()
            return rows
        else:
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()
            return [dict(r) for r in rows]

    def initialize_schema(self):
        """Read and execute schema.sql if database is not set up."""
        if self.db_type == "sqlite":
            schema_file = Config.BASE_DIR / "database" / "schema.sql"
            if schema_file.exists():
                with open(schema_file, "r", encoding="utf-8") as f:
                    schema_script = f.read()
                conn = self.get_connection()
                conn.executescript(schema_script)
                conn.commit()

    def seed_defaults(self):
        """Seed baseline fraud detection rules and initial demonstration accounts."""
        # 1. Seed Rules
        default_rules = [
            ("RULE_BLACKLIST", "Blacklist Entity Match", "Sender, receiver, IP, or device is on global blacklist", 100.0, 0.0, 1, "BLOCK"),
            ("RULE_VELOCITY_1M", "High Velocity (1 Min)", f"Exceeded {Config.VELOCITY_1MIN_MAX} transactions in 1 minute", 40.0, Config.VELOCITY_1MIN_MAX, 1, "REVIEW"),
            ("RULE_VELOCITY_10M", "High Velocity (10 Min)", f"Exceeded {Config.VELOCITY_10MIN_MAX} transactions in 10 minutes", 30.0, Config.VELOCITY_10MIN_MAX, 1, "REVIEW"),
            ("RULE_MICRO_BURST", "Micro-Transaction Testing", f"Multiple rapid transactions under $5.00", 35.0, Config.MICRO_TX_BURST_MAX, 1, "REVIEW"),
            ("RULE_HIGH_AMOUNT", "Excessive Single Transfer", f"Single transaction exceeding ${Config.MAX_SINGLE_TRANSACTION:,.2f}", 35.0, Config.MAX_SINGLE_TRANSACTION, 1, "REVIEW"),
            ("RULE_STRUCTURING", "Smurfing / Structuring", "Transaction structured just under reporting limits ($9k - $10k)", 50.0, Config.STRUCTURING_MIN, 1, "REVIEW"),
            ("RULE_RAPID_DRAIN", "Account Takeover / Rapid Drain", f"Transfer drains over {int(Config.RAPID_DRAIN_RATIO*100)}% of total account balance", 45.0, Config.RAPID_DRAIN_RATIO, 1, "REVIEW"),
            ("RULE_IMPOSSIBLE_TRAVEL", "Impossible Travel Speed", f"Geographic velocity exceeds {Config.MAX_REALISTIC_SPEED_KMH} km/h", 60.0, Config.MAX_REALISTIC_SPEED_KMH, 1, "BLOCK"),
            ("RULE_OFF_HOURS", "Unusual Off-Hours Transfer", "High-value transfer initiated between 01:00 AM and 05:00 AM", 25.0, 0.0, 1, "FLAG"),
            ("RULE_NEW_DEVICE", "Unrecognized Device Fingerprint", "Transaction attempted from unknown/new device", 20.0, 0.0, 1, "FLAG"),
            ("RULE_HISTORICAL_SPIKE", "Behavioral Spending Spike", "Amount is > 5x the user's historical 30-day average transfer size", 35.0, 5.0, 1, "REVIEW")
        ]

        for code, name, desc, weight, threshold, enabled, action in default_rules:
            row = self.fetch_one("SELECT id FROM rules_config WHERE rule_code = ?", (code,))
            if not row:
                self.execute(
                    """
                    INSERT INTO rules_config (rule_code, name, description, weight, threshold, is_enabled, action_if_triggered)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (code, name, desc, weight, threshold, enabled, action)
                )

        # 2. Seed Default Administrator
        admin_row = self.fetch_one("SELECT id FROM users WHERE username = ?", (Config.ADMIN_USERNAME,))
        if not admin_row:
            pwd_hash, salt = SecurityService.hash_password(Config.ADMIN_PASSWORD)
            cursor = self.execute(
                """
                INSERT INTO users (username, password_hash, salt, role, full_name, email, phone)
                VALUES (?, ?, ?, 'admin', 'System Administrator', ?, '+1-800-555-0199')
                """,
                (Config.ADMIN_USERNAME, pwd_hash, salt, Config.ADMIN_EMAIL)
            )
            admin_id = cursor.lastrowid
            # Admin wallet
            self.execute(
                """
                INSERT INTO wallets (user_id, wallet_number, balance, currency, status, daily_transfer_limit)
                VALUES (?, 'MW-ADMIN-0001', 50000.00, 'USD', 'active', 100000.00)
                """,
                (admin_id,)
            )

        # 3. Seed Demo Users & Wallets for immediate simulations
        demo_users = [
            ("alice", "Alice@12345", "Alice Wonderland", "alice@example.com", "+1-555-0101", "MW-1000000001", 3500.00, "dev-alice-ios-15"),
            ("bob", "Bob@12345", "Bob Builder", "bob@example.com", "+1-555-0102", "MW-1000000002", 2200.00, "dev-bob-android-12"),
            ("charlie", "Charlie@12345", "Charlie Brown", "charlie@example.com", "+1-555-0103", "MW-1000000003", 14500.00, "dev-charlie-mac-01"),
            ("mule_account", "Mule@12345", "Money Mule Target", "mule@darkweb.cc", "+1-555-0999", "MW-9999999999", 50.00, "dev-mule-unknown")
        ]

        for uname, pwd, name, email, phone, wnum, bal, dev in demo_users:
            if not self.fetch_one("SELECT id FROM users WHERE username = ?", (uname,)):
                p_hash, s = SecurityService.hash_password(pwd)
                cur = self.execute(
                    """
                    INSERT INTO users (username, password_hash, salt, role, full_name, email, phone, device_id)
                    VALUES (?, ?, ?, 'user', ?, ?, ?, ?)
                    """,
                    (uname, p_hash, s, name, email, phone, dev)
                )
                u_id = cur.lastrowid
                self.execute(
                    """
                    INSERT INTO wallets (user_id, wallet_number, balance, currency, status)
                    VALUES (?, ?, ?, 'USD', 'active')
                    """,
                    (u_id, wnum, bal)
                )

        # 4. Seed Known Blacklist Entry
        if not self.fetch_one("SELECT id FROM blacklist WHERE entity_type = 'WALLET' AND entity_value = 'MW-9999999999'"):
            self.execute(
                """
                INSERT INTO blacklist (entity_type, entity_value, reason, added_by)
                VALUES ('WALLET', 'MW-9999999999', 'Identified money laundering mule wallet in prior investigation', 'SYSTEM_SEED')
                """
            )
        if not self.fetch_one("SELECT id FROM blacklist WHERE entity_type = 'IP' AND entity_value = '198.51.100.23'"):
            self.execute(
                """
                INSERT INTO blacklist (entity_type, entity_value, reason, added_by)
                VALUES ('IP', '198.51.100.23', 'Tor exit node associated with credential stuffing', 'SYSTEM_SEED')
                """
            )
