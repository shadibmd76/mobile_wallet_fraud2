"""
Real-time Fraud Detection Engine.
Evaluates transactions across multi-layer behavioral, heuristic, and anomaly detection rules.
"""
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from app.config import Config
from app.db import Database
from app.security import SecurityService


class FraudEngine:
    def __init__(self, db: Optional[Database] = None):
        self.db = db or Database()

    def _get_active_rules(self) -> Dict[str, Dict[str, Any]]:
        """Fetch all active fraud rules and their configured weights."""
        rows = self.db.fetch_all("SELECT * FROM rules_config WHERE is_enabled = 1")
        return {r["rule_code"]: r for r in rows}

    def _is_blacklisted(self, entity_type: str, entity_value: str) -> Optional[Dict[str, Any]]:
        """Check if an entity is blacklisted."""
        if not entity_value:
            return None
        return self.db.fetch_one(
            "SELECT * FROM blacklist WHERE entity_type = ? AND LOWER(entity_value) = LOWER(?)",
            (entity_type, str(entity_value).strip())
        )

    def evaluate_transaction(
        self,
        sender_wallet: Dict[str, Any],
        receiver_wallet: Optional[Dict[str, Any]],
        amount: float,
        tx_type: str = "TRANSFER",
        location: Optional[Dict[str, Any]] = None,
        device_fingerprint: Optional[str] = None,
        tx_time: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """
        Evaluate a transaction against all active fraud rules.
        Returns detailed risk scoring, status recommendation, and triggered rules.
        """
        active_rules = self._get_active_rules()
        location = location or {}
        tx_time = tx_time or datetime.now()
        
        triggered_rules: List[Dict[str, Any]] = []
        raw_risk_score = 0.0
        forced_block = False
        forced_review = False
        reasons: List[str] = []

        sender_id = sender_wallet.get("id")
        sender_wallet_num = sender_wallet.get("wallet_number", "")
        receiver_wallet_num = receiver_wallet.get("wallet_number", "") if receiver_wallet else ""
        ip_addr = location.get("ip", "")

        # -------------------------------------------------------------
        # RULE 1: Blacklist Verification (Immediate Critical Match)
        # -------------------------------------------------------------
        if "RULE_BLACKLIST" in active_rules:
            bl_rule = active_rules["RULE_BLACKLIST"]
            bl_hits = []
            
            if sender_wallet_num and self._is_blacklisted("WALLET", sender_wallet_num):
                bl_hits.append(f"Sender wallet '{sender_wallet_num}' is blacklisted")
            if receiver_wallet_num and self._is_blacklisted("WALLET", receiver_wallet_num):
                bl_hits.append(f"Receiver wallet '{receiver_wallet_num}' is blacklisted")
            if ip_addr and self._is_blacklisted("IP", ip_addr):
                bl_hits.append(f"IP address '{ip_addr}' is blacklisted")
            if device_fingerprint and self._is_blacklisted("DEVICE", device_fingerprint):
                bl_hits.append(f"Device fingerprint is blacklisted")

            if bl_hits:
                triggered_rules.append({
                    "rule_code": "RULE_BLACKLIST",
                    "name": bl_rule["name"],
                    "weight": bl_rule["weight"],
                    "description": "; ".join(bl_hits)
                })
                raw_risk_score += bl_rule["weight"]
                forced_block = True
                reasons.extend(bl_hits)

        # -------------------------------------------------------------
        # RULE 2: Velocity Checks (1 Minute & 10 Minutes Window)
        # -------------------------------------------------------------
        if sender_id and ("RULE_VELOCITY_1M" in active_rules or "RULE_VELOCITY_10M" in active_rules):
            # Check 1-minute velocity
            one_min_ago = (tx_time - timedelta(minutes=1)).strftime("%Y-%m-%d %H:%M:%S")
            ten_min_ago = (tx_time - timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M:%S")

            count_1m_row = self.db.fetch_one(
                "SELECT COUNT(*) AS c FROM transactions WHERE sender_wallet_id = ? AND timestamp >= ?",
                (sender_id, one_min_ago)
            )
            count_1m = count_1m_row["c"] if count_1m_row else 0

            count_10m_row = self.db.fetch_one(
                "SELECT COUNT(*) AS c FROM transactions WHERE sender_wallet_id = ? AND timestamp >= ?",
                (sender_id, ten_min_ago)
            )
            count_10m = count_10m_row["c"] if count_10m_row else 0

            if "RULE_VELOCITY_1M" in active_rules:
                r1m = active_rules["RULE_VELOCITY_1M"]
                limit_1m = r1m["threshold"] or Config.VELOCITY_1MIN_MAX
                if count_1m >= limit_1m:
                    triggered_rules.append({
                        "rule_code": "RULE_VELOCITY_1M",
                        "name": r1m["name"],
                        "weight": r1m["weight"],
                        "description": f"Velocity anomaly: {count_1m} transfers executed in the past 60 seconds (Threshold: {limit_1m})"
                    })
                    raw_risk_score += r1m["weight"]
                    reasons.append(f"High velocity in 1 minute ({count_1m} transfers)")

            if "RULE_VELOCITY_10M" in active_rules:
                r10m = active_rules["RULE_VELOCITY_10M"]
                limit_10m = r10m["threshold"] or Config.VELOCITY_10MIN_MAX
                if count_10m >= limit_10m:
                    triggered_rules.append({
                        "rule_code": "RULE_VELOCITY_10M",
                        "name": r10m["name"],
                        "weight": r10m["weight"],
                        "description": f"High burst: {count_10m} transfers in the past 10 minutes (Threshold: {limit_10m})"
                    })
                    raw_risk_score += r10m["weight"]
                    reasons.append(f"High velocity in 10 minutes ({count_10m} transfers)")

        # -------------------------------------------------------------
        # RULE 3: Micro-Transaction Probing (Card / Balance Testing)
        # -------------------------------------------------------------
        if sender_id and "RULE_MICRO_BURST" in active_rules:
            rmicro = active_rules["RULE_MICRO_BURST"]
            one_min_ago = (tx_time - timedelta(minutes=1)).strftime("%Y-%m-%d %H:%M:%S")
            micro_row = self.db.fetch_one(
                """
                SELECT COUNT(*) AS c FROM transactions 
                WHERE sender_wallet_id = ? AND timestamp >= ? AND amount < 5.00
                """,
                (sender_id, one_min_ago)
            )
            micro_count = micro_row["c"] if micro_row else 0
            if amount < 5.00:
                micro_count += 1

            limit_micro = rmicro["threshold"] or Config.MICRO_TX_BURST_MAX
            if micro_count >= limit_micro:
                triggered_rules.append({
                    "rule_code": "RULE_MICRO_BURST",
                    "name": rmicro["name"],
                    "weight": rmicro["weight"],
                    "description": f"Detected {micro_count} rapid micro-transactions under $5.00 (Bot probing behavior)"
                })
                raw_risk_score += rmicro["weight"]
                reasons.append(f"Bot card-testing / micro-transaction burst ({micro_count} txs)")

        # -------------------------------------------------------------
        # RULE 4: Excessive Single Amount
        # -------------------------------------------------------------
        if "RULE_HIGH_AMOUNT" in active_rules:
            r_high = active_rules["RULE_HIGH_AMOUNT"]
            high_thresh = r_high["threshold"] or Config.MAX_SINGLE_TRANSACTION
            if amount > high_thresh:
                triggered_rules.append({
                    "rule_code": "RULE_HIGH_AMOUNT",
                    "name": r_high["name"],
                    "weight": r_high["weight"],
                    "description": f"Transaction amount ${amount:,.2f} exceeds single limit of ${high_thresh:,.2f}"
                })
                raw_risk_score += r_high["weight"]
                reasons.append(f"Single transfer amount exceeds threshold (${amount:,.2f})")

        # -------------------------------------------------------------
        # RULE 5: Structuring / Smurfing ($9,000 - $9,999.99)
        # -------------------------------------------------------------
        if "RULE_STRUCTURING" in active_rules:
            r_struct = active_rules["RULE_STRUCTURING"]
            if Config.STRUCTURING_MIN <= amount <= Config.STRUCTURING_MAX:
                triggered_rules.append({
                    "rule_code": "RULE_STRUCTURING",
                    "name": r_struct["name"],
                    "weight": r_struct["weight"],
                    "description": f"Potential structuring/smurfing: ${amount:,.2f} just under $10,000 reporting threshold"
                })
                raw_risk_score += r_struct["weight"]
                reasons.append(f"Suspected Anti-Money Laundering (AML) structuring (${amount:,.2f})")

        # -------------------------------------------------------------
        # RULE 6: Rapid Balance Drain (Account Takeover / Bust-out)
        # -------------------------------------------------------------
        if sender_wallet and "RULE_RAPID_DRAIN" in active_rules:
            balance = float(sender_wallet.get("balance", 0.0))
            if balance > 0:
                drain_ratio = amount / balance
                r_drain = active_rules["RULE_RAPID_DRAIN"]
                thresh_ratio = r_drain["threshold"] or Config.RAPID_DRAIN_RATIO
                if drain_ratio >= thresh_ratio and amount >= 100.0:
                    triggered_rules.append({
                        "rule_code": "RULE_RAPID_DRAIN",
                        "name": r_drain["name"],
                        "weight": r_drain["weight"],
                        "description": f"Transfer drains {drain_ratio * 100:.1f}% of current available balance (${balance:,.2f})"
                    })
                    raw_risk_score += r_drain["weight"]
                    reasons.append(f"Rapid balance drain ({drain_ratio*100:.1f}% of account)")

        # -------------------------------------------------------------
        # RULE 7: Impossible Travel (Geo-Velocity Anomaly)
        # -------------------------------------------------------------
        if sender_id and location and "lat" in location and "lon" in location and "RULE_IMPOSSIBLE_TRAVEL" in active_rules:
            r_geo = active_rules["RULE_IMPOSSIBLE_TRAVEL"]
            max_kmh = r_geo["threshold"] or Config.MAX_REALISTIC_SPEED_KMH
            
            # Retrieve last completed or pending transaction with location
            last_tx = self.db.fetch_one(
                """
                SELECT location, timestamp FROM transactions
                WHERE sender_wallet_id = ? AND location IS NOT NULL AND status IN ('COMPLETED', 'PENDING_REVIEW')
                ORDER BY timestamp DESC LIMIT 1
                """,
                (sender_id,)
            )
            if last_tx and last_tx.get("location"):
                try:
                    last_loc = json.loads(last_tx["location"])
                    if "lat" in last_loc and "lon" in last_loc:
                        # parse timestamp
                        last_time_str = last_tx["timestamp"]
                        last_time = datetime.fromisoformat(last_time_str) if "T" in last_time_str else datetime.strptime(last_time_str, "%Y-%m-%d %H:%M:%S")
                        elapsed_seconds = (tx_time - last_time).total_seconds()

                        # Only test if recent (within 24 hours) and positive elapsed time
                        if 0 < elapsed_seconds <= 86400:
                            dist_km = SecurityService.haversine_distance(
                                float(last_loc["lat"]), float(last_loc["lon"]),
                                float(location["lat"]), float(location["lon"])
                            )
                            speed_kmh = (dist_km / (elapsed_seconds / 3600.0)) if elapsed_seconds > 0 else float("inf")

                            if dist_km > 100.0 and speed_kmh > max_kmh:
                                desc = (
                                    f"Impossible travel detected: {dist_km:.1f} km traversed in "
                                    f"{elapsed_seconds/60:.1f} minutes ({speed_kmh:.1f} km/h > {max_kmh:.1f} km/h)"
                                )
                                triggered_rules.append({
                                    "rule_code": "RULE_IMPOSSIBLE_TRAVEL",
                                    "name": r_geo["name"],
                                    "weight": r_geo["weight"],
                                    "description": desc
                                })
                                raw_risk_score += r_geo["weight"]
                                reasons.append(f"Impossible geo-velocity ({speed_kmh:.0f} km/h)")
                                if r_geo.get("action_if_triggered") == "BLOCK":
                                    forced_block = True
                except Exception:
                    pass

        # -------------------------------------------------------------
        # RULE 8: Unusual Off-Hours High Transfer
        # -------------------------------------------------------------
        if "RULE_OFF_HOURS" in active_rules:
            r_hours = active_rules["RULE_OFF_HOURS"]
            hour = tx_time.hour
            if Config.OFF_HOURS_START <= hour < Config.OFF_HOURS_END and amount >= 500.00:
                triggered_rules.append({
                    "rule_code": "RULE_OFF_HOURS",
                    "name": r_hours["name"],
                    "weight": r_hours["weight"],
                    "description": f"High transfer initiated during abnormal off-hours window ({hour:02d}:00)"
                })
                raw_risk_score += r_hours["weight"]
                reasons.append(f"Off-hours high-value transfer at {hour:02d}:{tx_time.minute:02d}")

        # -------------------------------------------------------------
        # RULE 9: Unrecognized / New Device Fingerprint
        # -------------------------------------------------------------
        if sender_id and device_fingerprint and "RULE_NEW_DEVICE" in active_rules:
            r_dev = active_rules["RULE_NEW_DEVICE"]
            # Check if this sender has previous transactions with this device
            known_dev = self.db.fetch_one(
                """
                SELECT id FROM transactions 
                WHERE sender_wallet_id = ? AND device_fingerprint = ?
                LIMIT 1
                """,
                (sender_id, device_fingerprint)
            )
            # Check user registered device
            sender_user = self.db.fetch_one(
                "SELECT device_id FROM users u JOIN wallets w ON w.user_id = u.id WHERE w.id = ?",
                (sender_id,)
            )
            is_known = bool(known_dev) or (sender_user and sender_user.get("device_id") == device_fingerprint)
            if not is_known:
                triggered_rules.append({
                    "rule_code": "RULE_NEW_DEVICE",
                    "name": r_dev["name"],
                    "weight": r_dev["weight"],
                    "description": f"Transaction initiated from an unrecognized device hardware signature"
                })
                raw_risk_score += r_dev["weight"]
                reasons.append("Unrecognized device fingerprint")

        # -------------------------------------------------------------
        # RULE 10: Historical Spending Spike (> 5x normal average)
        # -------------------------------------------------------------
        if sender_id and "RULE_HISTORICAL_SPIKE" in active_rules:
            r_spike = active_rules["RULE_HISTORICAL_SPIKE"]
            avg_row = self.db.fetch_one(
                """
                SELECT AVG(amount) AS avg_amt, COUNT(*) AS count_tx
                FROM transactions
                WHERE sender_wallet_id = ? AND status = 'COMPLETED'
                """,
                (sender_id,)
            )
            if avg_row and avg_row["count_tx"] >= 3:
                avg_amt = float(avg_row["avg_amt"] or 0.0)
                multiplier = r_spike["threshold"] or 5.0
                if amount > (avg_amt * multiplier) and amount > 300.00:
                    triggered_rules.append({
                        "rule_code": "RULE_HISTORICAL_SPIKE",
                        "name": r_spike["name"],
                        "weight": r_spike["weight"],
                        "description": f"Transfer amount ${amount:,.2f} is significantly higher than historical average of ${avg_amt:,.2f}"
                    })
                    raw_risk_score += r_spike["weight"]
                    reasons.append(f"Spending spike ({amount/max(avg_amt,1):.1f}x higher than user avg)")

        # -------------------------------------------------------------
        # Final Decision Synthesis & Risk Grading
        # -------------------------------------------------------------
        risk_score = min(100.0, round(raw_risk_score, 2))

        if forced_block or risk_score >= Config.RISK_THRESHOLD_MEDIUM:
            status = "BLOCKED"
            risk_level = "CRITICAL" if risk_score >= 85.0 else "HIGH"
            approved = False
            requires_review = False
        elif risk_score >= Config.RISK_THRESHOLD_LOW or forced_review:
            status = "PENDING_REVIEW"
            risk_level = "MEDIUM"
            approved = False
            requires_review = True
        else:
            status = "COMPLETED"
            risk_level = "LOW"
            approved = True
            requires_review = False

        auto_freeze = (risk_score >= Config.AUTO_FREEZE_THRESHOLD)

        return {
            "approved": approved,
            "status": status,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "flagged_rules": triggered_rules,
            "reasons": reasons,
            "requires_review": requires_review,
            "auto_freeze": auto_freeze
        }
