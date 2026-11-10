"""
Configuration settings for the Mobile Wallet Fraud Detection System.
"""
import os
from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

class Config:
    BASE_DIR = BASE_DIR
    DATA_DIR = DATA_DIR
    # Database Settings
    DB_TYPE = os.getenv("MW_DB_TYPE", "sqlite").lower()  # 'sqlite' or 'mysql'
    SQLITE_PATH = str(DATA_DIR / "wallet.db")
    
    # MySQL Settings (used if DB_TYPE == 'mysql')
    MYSQL_HOST = os.getenv("MYSQL_HOST", "localhost")
    MYSQL_PORT = int(os.getenv("MYSQL_PORT", 3306))
    MYSQL_USER = os.getenv("MYSQL_USER", "root")
    MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD", "")
    MYSQL_DATABASE = os.getenv("MYSQL_DATABASE", "mobile_wallet_fraud")

    # Fraud Detection Thresholds
    RISK_THRESHOLD_LOW = 35.0      # < 35 -> Auto Approve
    RISK_THRESHOLD_MEDIUM = 70.0   # 35 - 69.9 -> Review Needed / Hold
    # >= 70 -> Decline / Block
    AUTO_FREEZE_THRESHOLD = 85.0   # >= 85 -> Instantly freeze sender wallet

    # Transaction Rules Limits
    MAX_SINGLE_TRANSACTION = 5000.00
    DAILY_LIMIT_DEFAULT = 10000.00
    
    # Structuring (Smurfing) Window ($9,000 - $9,999.99)
    STRUCTURING_MIN = 9000.00
    STRUCTURING_MAX = 9999.99

    # Velocity Limits
    VELOCITY_1MIN_MAX = 3
    VELOCITY_10MIN_MAX = 6
    MICRO_TX_BURST_MAX = 3       # Rapid low-amount transactions (< $5 in 60s)
    
    # Rapid Balance Drain (% of current wallet balance)
    RAPID_DRAIN_RATIO = 0.85     # Single transfer taking > 85% of account balance

    # Impossible Travel Speed (Kilometers per hour)
    MAX_REALISTIC_SPEED_KMH = 850.0

    # Off-Hours Fraud Window (24-hour format)
    OFF_HOURS_START = 1   # 01:00 AM
    OFF_HOURS_END = 5     # 05:00 AM

    # Security
    MAX_FAILED_LOGINS = 5
    PASSWORD_SALT_ROUNDS = 100_000

    # Default Seed Admin
    ADMIN_USERNAME = os.getenv("MW_ADMIN_USER", "admin")
    ADMIN_PASSWORD = os.getenv("MW_ADMIN_PASS", "Admin@12345")
    ADMIN_EMAIL = "admin@securewallet.internal"
