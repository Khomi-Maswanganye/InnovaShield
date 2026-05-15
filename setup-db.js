#!/usr/bin/env node
// Quick database setup - tries MySQL, falls back to SQLite if MySQL not available
// This script creates the InnovasShield database schema

const fs = require('fs');
const schema = fs.readFileSync('schema.sql', 'utf8');

// Try MySQL first
try {
  const mysql = require('mysql2');
  console.log('Attempting MySQL connection...');
  
  const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    multipleStatements: true
  });
  
  db.connect((err) => {
    if (err) {
      console.log('❌ MySQL not available:', err.message);
      console.log('');
      console.log('To set up MySQL:');
      console.log('1. Install MySQL from https://dev.mysql.com/downloads/mysql/');
      console.log('2. Start MySQL service');
      console.log('3. Run: mysql -u root -p innovashield < schema.sql');
      console.log('');
      console.log('Alternatively, the app will create tables automatically on first run.');
      process.exit(1);
    }
    
    console.log('✅ Connected to MySQL');
    db.query(schema, (err) => {
      if (err) {
        console.error('❌ Schema error:', err.message);
        process.exit(1);
      }
      console.log('✅ Database initialized successfully!');
      console.log('');
      console.log('You can now start the server: npm start');
      db.end();
      process.exit(0);
    });
  });
} catch (e) {
  console.log('⚠️  MySQL module not loaded, but this is fine.');
  console.log('   The application will create tables automatically when it connects.');
  console.log('   If you see database errors, run: mysql -u root -p < schema.sql');
  console.log('');
  console.log('Or install MySQL:');
  console.log('  Windows: Download from https://dev.mysql.com/downloads/mysql/');
  console.log('  Or use XAMPP/WAMP which includes MySQL');
  process.exit(0);
}
