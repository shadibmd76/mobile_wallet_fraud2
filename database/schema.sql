-- Mobile Wallet Fraud Detection & Prevention System
-- SQLite Relational Schema

PRAGMA foreign_keys = ON;

-- 1. Users Table
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user', -- 'admin', 'fraud_analyst', 'user'
    full_name TEXT,
    email TEXT UNIQUE,
    phone TEXT,
    device_id TEXT,
    is_active INTEGER DEFAULT 1,
    is_locked INTEGER DEFAULT 0,
    failed_logins INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 2. Wallets Table
CREATE TABLE IF NOT EXISTS wallets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    wallet_number TEXT UNIQUE NOT NULL,
    balance REAL NOT NULL DEFAULT 0.00,
    currency TEXT NOT NULL DEFAULT 'USD',
    status TEXT NOT NULL DEFAULT 'active', -- 'active', 'frozen', 'restricted'
    daily_transfer_limit REAL DEFAULT 5000.00,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- 3. Transactions Table
CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    transaction_uuid TEXT UNIQUE NOT NULL,
    sender_wallet_id INTEGER,
    receiver_wallet_id INTEGER,
    amount REAL NOT NULL,
    transaction_type TEXT NOT NULL, -- 'DEPOSIT', 'TRANSFER', 'WITHDRAWAL', 'BILL_PAY'
    status TEXT NOT NULL,           -- 'COMPLETED', 'PENDING_REVIEW', 'BLOCKED', 'FAILED'
    risk_score REAL DEFAULT 0.0,
    risk_level TEXT DEFAULT 'LOW',  -- 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    flagged_rules TEXT,             -- JSON string of triggered rule codes & descriptions
    location TEXT,                  -- JSON string {ip, city, country, lat, lon}
    device_fingerprint TEXT,
    notes TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (sender_wallet_id) REFERENCES wallets(id),
    FOREIGN KEY (receiver_wallet_id) REFERENCES wallets(id)
);

-- 4. Fraud Alerts Table
CREATE TABLE IF NOT EXISTS fraud_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    transaction_id INTEGER,
    wallet_id INTEGER,
    alert_type TEXT NOT NULL,
    risk_score REAL NOT NULL,
    reasons TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'OPEN', -- 'OPEN', 'INVESTIGATING', 'DISMISSED', 'CONFIRMED_FRAUD'
    action_taken TEXT DEFAULT 'FLAGGED', -- 'FLAGGED', 'BLOCKED', 'WALLET_FROZEN'
    analyst_notes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    resolved_at DATETIME,
    FOREIGN KEY (transaction_id) REFERENCES transactions(id) ON DELETE CASCADE,
    FOREIGN KEY (wallet_id) REFERENCES wallets(id) ON DELETE CASCADE
);

-- 5. Fraud Rules Configuration Table
CREATE TABLE IF NOT EXISTS rules_config (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_code TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    weight REAL NOT NULL DEFAULT 15.0,
    threshold REAL DEFAULT 0.0,
    is_enabled INTEGER DEFAULT 1,
    action_if_triggered TEXT DEFAULT 'FLAG' -- 'FLAG', 'REVIEW', 'BLOCK'
);

-- 6. Blacklist Table
CREATE TABLE IF NOT EXISTS blacklist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_type TEXT NOT NULL, -- 'WALLET', 'USER', 'IP', 'DEVICE'
    entity_value TEXT NOT NULL,
    reason TEXT,
    added_by TEXT DEFAULT 'SYSTEM',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(entity_type, entity_value)
);

-- 7. Audit Logs Table
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    action TEXT NOT NULL,
    details TEXT,
    ip_address TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- Indexes for high-speed fraud and transactional queries
CREATE INDEX IF NOT EXISTS idx_tx_sender ON transactions(sender_wallet_id);
CREATE INDEX IF NOT EXISTS idx_tx_receiver ON transactions(receiver_wallet_id);
CREATE INDEX IF NOT EXISTS idx_tx_timestamp ON transactions(timestamp);
CREATE INDEX IF NOT EXISTS idx_tx_status ON transactions(status);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON fraud_alerts(status);
CREATE INDEX IF NOT EXISTS idx_blacklist_lookup ON blacklist(entity_type, entity_value);
