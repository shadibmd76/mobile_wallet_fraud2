# 🛡️ Mobile Wallet Fraud Detection & Defense Platform

A production-grade, real-time transaction monitoring, behavioral analytics, and fraud attack simulation platform for digital mobile wallets.

---

## 🌟 Key Features

- **Real-Time Multi-Layer Fraud Engine**:
  - Evaluates every peer-to-peer transfer, withdrawal, and deposit instantaneously.
  - Dynamically computes an aggregate **Risk Score (0 to 100)** based on configurable weighted rule sets.
  - Automatic decision tiering:
    - **`APPROVED`** (Risk < 35.0): Seamless instant settlement.
    - **`PENDING_REVIEW`** (Risk 35.0 - 69.9): Transaction held in security queue; requires compliance officer adjudication.
    - **`BLOCKED`** (Risk >= 70.0): Malicious transfer declined.
    - **`AUTO-FREEZE`** (Risk >= 85.0): Immediate protective lockdown of compromised account.

- **10+ Pre-Configured Heuristic & Behavioral Fraud Rules**:
  1. `RULE_BLACKLIST`: Instant block on known fraudulent wallets, Tor/proxy IPs, compromised devices.
  2. `RULE_VELOCITY_1M`: Spikes exceeding velocity limits in 60 seconds (bot spammers).
  3. `RULE_VELOCITY_10M`: High-frequency burst transfers within 10 minutes.
  4. `RULE_MICRO_BURST`: Card/account probing with rapid micro-transfers under $5.00.
  5. `RULE_HIGH_AMOUNT`: Transfers exceeding single-transaction safety limits ($5,000.00).
  6. `RULE_STRUCTURING`: Anti-Money Laundering (AML) smurfing just under reporting thresholds ($9,000 - $9,999.99).
  7. `RULE_RAPID_DRAIN`: Account Takeover signature where > 85% of total balance is drained at once.
  8. `RULE_IMPOSSIBLE_TRAVEL`: Geo-velocity calculation (Haversine formula); flags physical travel speeds > 850 km/h.
  9. `RULE_OFF_HOURS`: High-value unusual activity initiated during late night windows (01:00 AM - 05:00 AM).
  10. `RULE_NEW_DEVICE`: Unrecognized hardware / browser fingerprint signatures.
  11. `RULE_HISTORICAL_SPIKE`: Transfers exceeding 5x the account holder's 30-day baseline average.

- **Attack Simulator Lab**:
  - One-click synthetic attack simulator that models real-world attack vectors:
    - ⚡ Normal legitimate everyday transfers
    - 🚨 Account Takeover (ATO) & sudden 92% balance drain from an overseas IP
    - ⚡ Rapid-fire velocity burst attack (5 consecutive transfers in seconds)
    - 🤖 Card testing bot probing
    - ✈️ Impossible travel (New York ➔ London in 15 minutes)
    - 💼 AML Smurfing & Structuring ($9,850.00)
    - 🛑 Blacklisted recipient hit
    - 🎲 Mixed batch generator (15 transactions with customizable fraud ratio)

- **Desktop-Based Workstation First (`gui.py`)**:
  - Native Windows desktop application with zero external framework dependencies (uses standard Tkinter/TTK).
  - 5 integrated analyst and user tabs:
    1. 📱 **User Mobile Wallet**: Balance overview, deposits, P2P transfers, live visual Risk Gauge.
    2. 🚨 **Fraud Center & Alerts**: Incident queue with one-click Approve, Block, Dismiss & Freeze actions.
    3. ⚙️ **Fraud Rules Engine**: Live tuning of detection weights and enforcement policies.
    4. 🧪 **Attack Simulator Lab**: Trigger real-time cyber attacks and monitor live detection stream.
    5. 📊 **Forensic Reports & SQL Analytics**: Run analytical queries (Smurfing, Velocity Spikes, Audit Trail).
  - Dedicated **Forensic Transaction Inspector** modal on double-click.

- **Dual Interfaces (Desktop GUI & Terminal CLI)**:
  - Running `python main.py` or double-clicking `run.bat` automatically launches the Desktop GUI by default.
  - Interactive Terminal CLI accessible via `python main.py --cli` or `run.bat --cli`.

- **Dual Database Architecture**:
  - **SQLite**: Embedded default with zero configuration required.
  - **MySQL**: Full MySQL 8.x enterprise schema included (`schema_mysql.sql`).

- **Unit & Integration Test Suite**:
  - 100% automated test coverage across authentication, wallet mechanics, and all fraud detection rules.

---

## 📂 Project Directory Structure

```text
mobile_wallet_fraud/
├── app/
│   ├── __init__.py          # Package initialization & exports
│   ├── admin.py             # Case review, blacklist, alert adjudication, metrics
│   ├── auth.py              # User registration, login, lockouts, PBKDF2 hashing
│   ├── config.py            # Thresholds, velocity limits, DB configurations
│   ├── db.py                # Database abstraction, connection pool, seed data
│   ├── fraud_engine.py      # Core behavioral & heuristic risk scoring engine
│   ├── security.py          # Cryptography, salt generation, Haversine geo-distance
│   ├── simulator.py         # Synthetic traffic & fraud attack generator
│   └── wallet.py            # Wallet deposits, withdrawals, P2P transfers
├── database/
│   ├── queries.sql          # Forensic & analytical SQL queries
│   ├── schema.sql           # SQLite schema DDL with indexing
│   └── schema_mysql.sql     # MySQL 8.0+ enterprise schema DDL
├── tests/
│   ├── __init__.py
│   ├── test_auth.py         # Auth, password hashing & lockout tests
│   ├── test_fraud_engine.py # Rule evaluations, impossible travel, structuring
│   └── test_wallet.py       # Balance checks, transfer lifecycle, deposits
├── gui.py                   # Desktop Tkinter Graphical User Interface
├── main.py                  # Interactive CLI and application entry point
├── requirements.txt         # Optional enhancements & drivers
├── run.bat                  # Windows one-click launcher
└── run.sh                   # Linux/macOS launcher script
```

---

## 🚀 Quick Start Guide

### Prerequisites
- Python 3.9 or higher (Python 3.10+ recommended)
- Standard library modules (`sqlite3`, `hashlib`, `tkinter`, `unittest`) are used by default.

### Installation

1. **Clone or navigate to the project directory**:
   ```bash
   cd mobile_wallet_fraud
   ```

2. *(Optional)* Install test and styling enhancements:
   ```bash
   pip install -r requirements.txt
   ```

---

## 🖥️ Running the Application

### 1. Launch the Desktop Application (Default)
Simply run `python main.py` or double-click `run.bat`:
```bash
python main.py
# OR (Windows double-click)
run.bat
```

### 2. Optional: Create a Desktop Shortcut on Windows
To place a 1-click shortcut on your Windows Desktop:
```cmd
create_desktop_shortcut.bat
```

### 3. Launch the Interactive Terminal CLI (Optional)
If you prefer terminal mode instead of the desktop GUI:
```bash
python main.py --cli
# OR (Windows)
run.bat --cli
```

### 4. Run the Automated Test Suite
```bash
python -m unittest discover -s tests -v
# OR (Windows)
run.bat --test
```

---

## 🧪 Simulation Scenarios & Walkthrough

The platform includes seeded accounts ready for immediate demonstration:
- **`alice`** (Balance: $3,500.00 | Wallet: `MW-1000000001`)
- **`bob`** (Balance: $2,200.00 | Wallet: `MW-1000000002`)
- **`charlie`** (Balance: $14,500.00 | Wallet: `MW-1000000003`)
- **`mule_account`** (Blacklisted Target | Wallet: `MW-9999999999`)
- **`admin`** (`admin` / `Admin@12345`)

### Attack Demonstrations in Simulator:
1. **Impossible Travel Anomaly**:
   - Executes a baseline payment from New York (`40.7128, -74.0060`).
   - 15 minutes later, an attempt is made from London (`51.5074, -0.1278`).
   - Velocity calculated: `> 22,000 km/h` (exceeds max 850 km/h threshold).
   - **Verdict**: `BLOCKED` with Critical risk rating.

2. **Account Takeover & Rapid Drain**:
   - Attacker logs in from a previously unseen device fingerprint during off-hours (03:15 AM).
   - Attempts to drain 92% of the victim's wallet balance in a single transaction.
   - **Verdict**: Triggers `RULE_RAPID_DRAIN`, `RULE_OFF_HOURS`, and `RULE_NEW_DEVICE`. Transaction is blocked and account is automatically frozen.

3. **Anti-Money Laundering (AML) Smurfing**:
   - Attacker attempts a transfer of **$9,850.00** to evade the standard $10,000.00 currency reporting limit.
   - **Verdict**: Triggers `RULE_STRUCTURING` and `RULE_HIGH_AMOUNT`, placing funds on administrative hold (`PENDING_REVIEW`).

---

## 📊 Compliance & Forensic Queries

The `database/queries.sql` file includes specialized analytical queries:
- Top accounts by open fraud alert volume.
- Real-time transaction velocity in the last 10 minutes.
- Rolling fraud block rates and total protected USD volume.
- Smurfing detection between $9,000.00 and $9,999.99.
- Complete audit trails of administrative releases and wallet freezes.

---

## 🔒 Security Architecture

- **Passphrase Security**: Passwords are salted using cryptographically secure 16-byte random salts and hashed via **PBKDF2-HMAC-SHA256** with 100,000 iterations.
- **Account Lockout Policy**: 5 consecutive failed login attempts automatically lock the user account.
- **Atomic Financial Transactions**: Database operations utilize ACID transactions with automatic rollback to ensure zero balance discrepancies.
- **Constant-Time Verification**: Verification routines employ `hmac.compare_digest` to prevent timing attack side-channels.
