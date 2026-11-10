-- Mobile Wallet Fraud Forensic & Analytical SQL Queries

-- 1. Top 10 High-Risk Wallets by Open Fraud Alerts
SELECT 
    w.id AS wallet_id,
    w.wallet_number,
    u.username,
    u.email,
    w.balance,
    w.status AS wallet_status,
    COUNT(fa.id) AS alert_count,
    ROUND(AVG(fa.risk_score), 2) AS avg_risk_score,
    MAX(fa.risk_score) AS max_risk_score
FROM wallets w
JOIN users u ON w.user_id = u.id
JOIN fraud_alerts fa ON fa.wallet_id = w.id
WHERE fa.status IN ('OPEN', 'INVESTIGATING')
GROUP BY w.id, w.wallet_number, u.username, u.email, w.balance, w.status
ORDER BY alert_count DESC, max_risk_score DESC
LIMIT 10;

-- 2. Transaction Velocity Analysis (Transactions in past 10 minutes)
SELECT 
    sender_wallet_id,
    COUNT(*) AS tx_count_10min,
    ROUND(SUM(amount), 2) AS total_amount_transferred
FROM transactions
WHERE timestamp >= datetime('now', '-10 minutes')
  AND transaction_type IN ('TRANSFER', 'WITHDRAWAL')
GROUP BY sender_wallet_id
HAVING tx_count_10min >= 3
ORDER BY tx_count_10min DESC;

-- 3. Overall Fraud Ratio & System Summary
SELECT 
    COUNT(*) AS total_transactions,
    SUM(CASE WHEN status = 'COMPLETED' THEN 1 ELSE 0 END) AS approved_count,
    SUM(CASE WHEN status = 'PENDING_REVIEW' THEN 1 ELSE 0 END) AS review_count,
    SUM(CASE WHEN status = 'BLOCKED' THEN 1 ELSE 0 END) AS blocked_count,
    ROUND(AVG(risk_score), 2) AS overall_avg_risk_score,
    ROUND((100.0 * SUM(CASE WHEN status = 'BLOCKED' THEN 1 ELSE 0 END)) / MAX(COUNT(*), 1), 2) AS fraud_block_rate_percent,
    ROUND(SUM(amount), 2) AS total_volume_usd
FROM transactions;

-- 4. Detect Potential Structuring / Smurfing ($9,000 - $9,999)
SELECT 
    t.id,
    t.transaction_uuid,
    t.sender_wallet_id,
    w.wallet_number AS sender_wallet,
    t.amount,
    t.risk_score,
    t.status,
    t.timestamp
FROM transactions t
JOIN wallets w ON t.sender_wallet_id = w.id
WHERE t.amount BETWEEN 9000.00 AND 9999.99
ORDER BY t.timestamp DESC;

-- 5. Sudden Account Balance Drain (Transfers > 80% of wallet balance)
SELECT 
    t.transaction_uuid,
    u.username AS account_holder,
    w.wallet_number,
    t.amount AS transfer_amount,
    w.balance AS current_balance,
    t.risk_score,
    t.flagged_rules,
    t.timestamp
FROM transactions t
JOIN wallets w ON t.sender_wallet_id = w.id
JOIN users u ON w.user_id = u.id
WHERE t.risk_score >= 50
  AND t.transaction_type IN ('TRANSFER', 'WITHDRAWAL')
ORDER BY t.timestamp DESC
LIMIT 20;

-- 6. Most Frequently Triggered Fraud Detection Rules
SELECT 
    alert_type,
    COUNT(*) AS occurrences,
    ROUND(AVG(risk_score), 2) AS avg_rule_risk_score
FROM fraud_alerts
GROUP BY alert_type
ORDER BY occurrences DESC;

-- 7. Audit Trail of Admin Interventions
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
LIMIT 50;
