#!/usr/bin/env node
// Reset database - drops and recreates everything

const mysql = require('mysql2');
const fs = require('fs');

const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    multipleStatements: true
});

db.connect((err) => {
    if (err) {
        console.error('❌ MySQL connection failed:', err.message);
        process.exit(1);
    }
    
    console.log('🔄 Resetting tables...');
    const schema = `
        USE innovashield;
        SET FOREIGN_KEY_CHECKS=0;
        DROP TABLE IF EXISTS watchlist;
        DROP TABLE IF EXISTS patent_queue;
        DROP TABLE IF EXISTS ownership_changes;
        DROP TABLE IF EXISTS patents;
        DROP TABLE IF EXISTS trademarks;
        DROP TABLE IF EXISTS users;
        SET FOREIGN_KEY_CHECKS=1;
        
        CREATE TABLE users (
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
        
        CREATE TABLE patents (
            patent_id INT AUTO_INCREMENT PRIMARY KEY,
            patent_number VARCHAR(50) UNIQUE NOT NULL,
            title TEXT NOT NULL,
            owner VARCHAR(255) DEFAULT 'Unknown',
            industry VARCHAR(100),
            filing_date DATE,
            expiry_date DATE,
            status ENUM('Active','Expired') DEFAULT 'Active',
            description TEXT,
            source VARCHAR(50) NOT NULL DEFAULT 'USPTO',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_source (source),
            INDEX idx_status (status),
            INDEX idx_industry (industry),
            INDEX idx_expiry (expiry_date)
        );
        
        CREATE TABLE trademarks (
            trademark_id INT AUTO_INCREMENT PRIMARY KEY,
            trademark_number VARCHAR(50) UNIQUE NOT NULL,
            name TEXT NOT NULL,
            owner VARCHAR(255) DEFAULT 'Unknown',
            industry VARCHAR(100),
            registration_date DATE,
            expiry_date DATE,
            status VARCHAR(50) DEFAULT 'Pending',
            source VARCHAR(50) NOT NULL DEFAULT 'USPTO',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_source (source),
            INDEX idx_status (status),
            INDEX idx_industry (industry),
            INDEX idx_expiry (expiry_date)
        );
        
        CREATE TABLE watchlist (
            watchlist_id INT AUTO_INCREMENT PRIMARY KEY,
            patent_id INT NULL,
            trademark_id INT NULL,
            user_id VARCHAR(100),
            notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        
        CREATE TABLE patent_queue (
            queue_id INT AUTO_INCREMENT PRIMARY KEY,
            patent_number VARCHAR(50),
            title TEXT,
            applicant_name VARCHAR(255),
            filing_date DATE,
            status VARCHAR(50) DEFAULT 'Pending',
            submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        
        CREATE TABLE ownership_changes (
            change_id INT AUTO_INCREMENT PRIMARY KEY,
            patent_id INT,
            old_owner VARCHAR(255),
            new_owner VARCHAR(255),
            change_date DATE,
            recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    `;
    
    db.query(schema, (err) => {
        if (err) {
            console.error('❌ Reset error:', err.message);
            process.exit(1);
        }
        
        console.log('✅ Tables recreated successfully!');
        db.end();
        process.exit(0);
    });
});
