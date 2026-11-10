"""
Security, Cryptography, and Mathematical Helpers for Fraud Detection.
"""
import hashlib
import hmac
import math
import os
import secrets
import uuid
from typing import Optional, Tuple
from app.config import Config

try:
    import bcrypt  # type: ignore
    HAS_BCRYPT = True
except ImportError:
    HAS_BCRYPT = False


class SecurityService:
    @staticmethod
    def generate_salt(length: int = 16) -> str:
        """Generate a cryptographically secure random hexadecimal salt."""
        return secrets.token_hex(length)

    @classmethod
    def hash_password(cls, password: str, salt: Optional[str] = None) -> Tuple[str, str]:
        """
        Hash a plaintext password using PBKDF2-HMAC-SHA256 with a unique salt.
        Returns: (password_hash, salt)
        """
        if salt is None:
            salt = cls.generate_salt()
        
        # PBKDF2 with SHA-256
        pwd_bytes = password.encode('utf-8')
        salt_bytes = salt.encode('utf-8')
        key = hashlib.pbkdf2_hmac(
            'sha256',
            pwd_bytes,
            salt_bytes,
            Config.PASSWORD_SALT_ROUNDS
        )
        return key.hex(), salt

    @classmethod
    def verify_password(cls, password: str, stored_hash: str, salt: str) -> bool:
        """
        Constant-time verification of candidate password against stored hash.
        """
        computed_hash, _ = cls.hash_password(password, salt)
        return hmac.compare_digest(computed_hash, stored_hash)

    @staticmethod
    def generate_uuid() -> str:
        """Generate standard UUIDv4 string for transactions."""
        return str(uuid.uuid4())

    @staticmethod
    def generate_wallet_number() -> str:
        """Generate a random 10-digit mobile wallet account number."""
        num = secrets.randbelow(9000000000) + 1000000000
        return f"MW-{num}"

    @staticmethod
    def compute_device_fingerprint(raw_device_info: str) -> str:
        """Compute SHA-256 hash representing a unique device fingerprint."""
        return hashlib.sha256(raw_device_info.strip().encode('utf-8')).hexdigest()

    @staticmethod
    def haversine_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        """
        Calculate the great-circle distance between two points on Earth (in Kilometers).
        """
        r = 6371.0  # Earth radius in km
        phi1 = math.radians(lat1)
        phi2 = math.radians(lat2)
        delta_phi = math.radians(lat2 - lat1)
        delta_lambda = math.radians(lon2 - lon1)

        a = (math.sin(delta_phi / 2.0) ** 2 +
             math.cos(phi1) * math.cos(phi2) * (math.sin(delta_lambda / 2.0) ** 2))
        c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))
        return r * c

    @classmethod
    def calculate_travel_speed_kmh(
        cls, 
        loc1: dict, 
        loc2: dict, 
        time_elapsed_seconds: float
    ) -> float:
        """
        Calculate velocity in km/h between two geographical points.
        loc: {'lat': float, 'lon': float}
        """
        if time_elapsed_seconds <= 0:
            return float('inf')

        lat1, lon1 = loc1.get('lat', 0.0), loc1.get('lon', 0.0)
        lat2, lon2 = loc2.get('lat', 0.0), loc2.get('lon', 0.0)

        distance_km = cls.haversine_distance(lat1, lon1, lat2, lon2)
        hours = time_elapsed_seconds / 3600.0
        return distance_km / hours
