-- ============================================================
-- DB Sentinel — Database Schema
-- ============================================================

CREATE DATABASE IF NOT EXISTS db_sentinel;
USE db_sentinel;

-- Users table for authentication & RBAC
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(80) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) DEFAULT 'analyst',
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL,
    INDEX idx_username (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Synthetic Employee Records (Confidential Data for Testing)
CREATE TABLE IF NOT EXISTS employees (
    employee_id INT AUTO_INCREMENT PRIMARY KEY,
    first_name VARCHAR(50) NOT NULL,
    last_name VARCHAR(50) NOT NULL,
    email VARCHAR(100) UNIQUE,
    phone VARCHAR(20),
    department VARCHAR(50) NOT NULL,
    designation VARCHAR(80) NOT NULL,
    salary DECIMAL(12, 2) NOT NULL,
    gender VARCHAR(10) NOT NULL,
    date_of_birth DATE,
    hire_date DATE NOT NULL,
    address VARCHAR(200),
    city VARCHAR(50),
    state VARCHAR(50),
    ssn_last4 CHAR(4),
    performance_rating DECIMAL(3, 1),
    INDEX idx_department (department),
    INDEX idx_designation (designation),
    INDEX idx_salary (salary)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Query Logs
CREATE TABLE IF NOT EXISTS query_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    query_text TEXT NOT NULL,
    risk_score DECIMAL(5, 4) DEFAULT 0,
    classification VARCHAR(20) DEFAULT 'SAFE',
    is_blocked BOOLEAN DEFAULT FALSE,
    attack_types JSON,
    details JSON,
    ml_score DECIMAL(5, 4) DEFAULT 0,
    rule_score DECIMAL(5, 4) DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_user_id (user_id),
    INDEX idx_classification (classification),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Security Alerts
CREATE TABLE IF NOT EXISTS security_alerts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    query_log_id INT NULL,
    user_id INT NOT NULL,
    severity VARCHAR(20) NOT NULL,
    attack_type VARCHAR(100) NOT NULL,
    description TEXT NOT NULL,
    details JSON,
    is_reviewed BOOLEAN DEFAULT FALSE,
    reviewed_by INT NULL,
    reviewed_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (query_log_id) REFERENCES query_logs(id) ON DELETE SET NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (reviewed_by) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_severity (severity),
    INDEX idx_is_reviewed (is_reviewed),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Audit Logs with SHA-256 Tamper-Evident Hash Chain
CREATE TABLE IF NOT EXISTS audit_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NULL,
    action VARCHAR(100) NOT NULL,
    details TEXT,
    prev_hash VARCHAR(64) DEFAULT '0000000000000000000000000000000000000000000000000000000000000000',
    hash VARCHAR(64) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
