-- Mobile Wallet Fraud Detection & Prevention System
-- MySQL Relational Schema (MySQL 8.0+)

CREATE DATABASE IF NOT EXISTS mobile_wallet_fraud CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE mobile_wallet_fraud;

SET FOREIGN_KEY_CHECKS = 0;
DROP TABLE IF EXISTS audit_logs;
DROP TABLE IF EXISTS blacklist;
DROP TABLE IF EXISTS rules_config;
DROP TABLE IF EXISTS fraud_alerts;
DROP TABLE IF EXISTS transactions;
DROP TABLE IF EXISTS wallets;
DROP TABLE IF EXISTS users;
SET FOREIGN_KEY_CHECKS = 1;

-- 1. Users Table
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    salt VARCHAR(64) NOT NULL,
    role ENUM('admin', 'fraud_analyst', 'user') NOT NULL DEFAULT 'user',
    full_name VARCHAR(100),
    email VARCHAR(100) UNIQUE,
    phone VARCHAR(30),
    device_id VARCHAR(100),
    is_active TINYINT(1) DEFAULT 1,
    is_locked TINYINT(1) DEFAULT 0,
    failed_logins INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 2. Wallets Table
CREATE TABLE wallets (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    wallet_number VARCHAR(32) NOT NULL UNIQUE,
    balance DECIMAL(15,2) NOT NULL DEFAULT 0.00,
    currency VARCHAR(10) NOT NULL DEFAULT 'USD',
    status ENUM('active', 'frozen', 'restricted') NOT NULL DEFAULT 'active',
    daily_transfer_limit DECIMAL(15,2) DEFAULT 5000.00,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 3. Transactions Table
CREATE TABLE transactions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    transaction_uuid VARCHAR(64) NOT NULL UNIQUE,
    sender_wallet_id INT NULL,
    receiver_wallet_id INT NULL,
    amount DECIMAL(15,2) NOT NULL,
    transaction_type ENUM('DEPOSIT', 'TRANSFER', 'WITHDRAWAL', 'BILL_PAY') NOT NULL,
    status ENUM('COMPLETED', 'PENDING_REVIEW', 'BLOCKED', 'FAILED') NOT NULL,
    risk_score DECIMAL(5,2) DEFAULT 0.00,
    risk_level ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') DEFAULT 'LOW',
    flagged_rules JSON,
    location JSON,
    device_fingerprint VARCHAR(128),
    notes TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (sender_wallet_id) REFERENCES wallets(id) ON DELETE SET NULL,
    FOREIGN KEY (receiver_wallet_id) REFERENCES wallets(id) ON DELETE SET NULL,
    INDEX idx_tx_sender (sender_wallet_id),
    INDEX idx_tx_receiver (receiver_wallet_id),
    INDEX idx_tx_timestamp (timestamp),
    INDEX idx_tx_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 4. Fraud Alerts Table
CREATE TABLE fraud_alerts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    transaction_id INT NULL,
    wallet_id INT NOT NULL,
    alert_type VARCHAR(100) NOT NULL,
    risk_score DECIMAL(5,2) NOT NULL,
    reasons JSON NOT NULL,
    status ENUM('OPEN', 'INVESTIGATING', 'DISMISSED', 'CONFIRMED_FRAUD') NOT NULL DEFAULT 'OPEN',
    action_taken ENUM('FLAGGED', 'BLOCKED', 'WALLET_FROZEN') DEFAULT 'FLAGGED',
    analyst_notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP NULL,
    FOREIGN KEY (transaction_id) REFERENCES transactions(id) ON DELETE CASCADE,
    FOREIGN KEY (wallet_id) REFERENCES wallets(id) ON DELETE CASCADE,
    INDEX idx_alerts_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 5. Fraud Rules Configuration Table
CREATE TABLE rules_config (
    id INT AUTO_INCREMENT PRIMARY KEY,
    rule_code VARCHAR(50) NOT NULL UNIQUE,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    weight DECIMAL(5,2) NOT NULL DEFAULT 15.00,
    threshold DECIMAL(15,2) DEFAULT 0.00,
    is_enabled TINYINT(1) DEFAULT 1,
    action_if_triggered ENUM('FLAG', 'REVIEW', 'BLOCK') DEFAULT 'FLAG'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 6. Blacklist Table
CREATE TABLE blacklist (
    id INT AUTO_INCREMENT PRIMARY KEY,
    entity_type ENUM('WALLET', 'USER', 'IP', 'DEVICE') NOT NULL,
    entity_value VARCHAR(150) NOT NULL,
    reason TEXT,
    added_by VARCHAR(50) DEFAULT 'SYSTEM',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uk_entity (entity_type, entity_value)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 7. Audit Logs Table
CREATE TABLE audit_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NULL,
    action VARCHAR(100) NOT NULL,
    details TEXT,
    ip_address VARCHAR(45),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
