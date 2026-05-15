-- InnovaShield Database Schema
-- Run: mysql -u root -p < schema.sql

CREATE DATABASE IF NOT EXISTS innovashield;
USE innovashield;

-- Users table (for authentication and role-based access)
CREATE TABLE IF NOT EXISTS users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(255),
    role ENUM('Admin','Analyst','Viewer') DEFAULT 'Viewer',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL,
    INDEX idx_username (username),
    INDEX idx_role (role)
);

-- Patents table (stores records from USPTO PatentsView)
CREATE TABLE IF NOT EXISTS patents (
    patent_id INT AUTO_INCREMENT PRIMARY KEY,
    patent_number VARCHAR(50) UNIQUE NOT NULL,
    title TEXT NOT NULL,
    owner VARCHAR(255) DEFAULT 'Unknown',
    industry VARCHAR(100),
    filing_date DATE,
    expiry_date DATE,
    status ENUM('Active','Expired') DEFAULT 'Active',
    description TEXT,
    source ENUM('USPTO') NOT NULL DEFAULT 'USPTO',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_source (source),
    INDEX idx_status (status),
    INDEX idx_industry (industry),
    INDEX idx_expiry (expiry_date)
);

-- Trademarks table (stores records from USPTO Trademark TSDR)
CREATE TABLE IF NOT EXISTS trademarks (
    trademark_id INT AUTO_INCREMENT PRIMARY KEY,
    trademark_number VARCHAR(50) UNIQUE NOT NULL,
    name TEXT NOT NULL,
    owner VARCHAR(255) DEFAULT 'Unknown',
    industry VARCHAR(100),
    registration_date DATE,
    expiry_date DATE,
    status ENUM('Active','Pending','Renewed') DEFAULT 'Pending',
    source ENUM('USPTO') NOT NULL DEFAULT 'USPTO',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_source (source),
    INDEX idx_status (status),
    INDEX idx_industry (industry),
    INDEX idx_expiry (expiry_date)
);

-- Watchlist table (links to patents OR trademarks)
CREATE TABLE IF NOT EXISTS watchlist (
    watchlist_id INT AUTO_INCREMENT PRIMARY KEY,
    patent_id INT NULL,
    trademark_id INT NULL,
    user_id VARCHAR(100),
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (patent_id) REFERENCES patents(patent_id) ON DELETE CASCADE,
    FOREIGN KEY (trademark_id) REFERENCES trademarks(trademark_id) ON DELETE CASCADE,
    CHECK (patent_id IS NOT NULL OR trademark_id IS NOT NULL)
);

-- Patent queue (for manual submission tracking)
CREATE TABLE IF NOT EXISTS patent_queue (
    queue_id INT AUTO_INCREMENT PRIMARY KEY,
    patent_number VARCHAR(50),
    title TEXT,
    applicant_name VARCHAR(255),
    filing_date DATE,
    status ENUM('Pending','Processing','Approved','Rejected') DEFAULT 'Pending',
    submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Ownership changes log
CREATE TABLE IF NOT EXISTS ownership_changes (
    change_id INT AUTO_INCREMENT PRIMARY KEY,
    patent_id INT,
    old_owner VARCHAR(255),
    new_owner VARCHAR(255),
    change_date DATE,
    recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (patent_id) REFERENCES patents(patent_id) ON DELETE SET NULL
);