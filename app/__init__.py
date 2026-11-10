"""
Mobile Wallet Fraud Detection & Prevention Platform
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
A comprehensive real-time transaction monitoring, behavioral analytics,
and fraud simulation system for digital mobile wallets.
"""

__version__ = "1.0.0"
__author__ = "Mobile Wallet Fraud Team"

from app.config import Config
from app.db import Database
from app.fraud_engine import FraudEngine
from app.wallet import WalletService
from app.auth import AuthService
from app.admin import AdminService
from app.simulator import FraudSimulator

__all__ = [
    "Config",
    "Database",
    "FraudEngine",
    "WalletService",
    "AuthService",
    "AdminService",
    "FraudSimulator",
]
