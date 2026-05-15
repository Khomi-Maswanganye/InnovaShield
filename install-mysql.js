#!/usr/bin/env node
// MySQL installer script for Windows - downloads and installs MySQL Community Server
// Run as Administrator for best results

const { exec } = require('child_process');
const https = require('https');
const fs = require('fs');
const path = require('path');

const MYSQL_VERSION = '8.0.39';
const INSTALLER_URL = `https://dev.mysql.com/get/Downloads/MySQL-Shell/mysql-shell-${MYSQL_VERSION}-winx64.msi`;
const DOWNLOAD_PATH = path.join(__dirname, 'mysql-installer.msi');

console.log('='.repeat(60));
console.log('MySQL Installation for InnovaShield');
console.log('='.repeat(60));
console.log('');

function downloadInstaller() {
  return new Promise((resolve, reject) => {
    console.log(`📥 Downloading MySQL ${MYSQL_VERSION} installer...`);
    console.log(`   from: ${INSTALLER_URL}`);
    
    const file = fs.createWriteStream(DOWNLOAD_PATH);
    https.get(INSTALLER_URL, (response) => {
      if (response.statusCode === 200) {
        response.pipe(file);
        file.on('finish', () => {
          file.close();
          console.log('✅ Download complete!');
          resolve();
        });
      } else {
        reject(new Error(`HTTP ${response.statusCode}: ${response.statusMessage}`));
      }
    }).on('error', (err) => {
      fs.unlink(DOWNLOAD_PATH, () => {});
      reject(err);
    });
  });
}

function runInstaller() {
  return new Promise((resolve, reject) => {
    console.log('');
    console.log('📦 Installing MySQL...');
    console.log('   This will open the MySQL installer window.');
    console.log('   Please follow these steps in the GUI:');
    console.log('   1. Choose "Developer Default" or "Custom"');
    console.log('   2. Set root password to blank (or remember it)');
    console.log('   3. Keep default port 3306');
    console.log('   4. Complete installation');
    console.log('');
    
    const cmd = `msiexec /i "${DOWNLOAD_PATH}"`;
    exec(cmd, (error, stdout, stderr) => {
      if (error) {
        console.log('⚠️  Installer may require manual completion.');
        console.log('   If installation fails, you can:');
        console.log('   - Download manually from: https://dev.mysql.com/downloads/mysql/');
        console.log('   - Use XAMPP/WAMP which includes MySQL');
        console.log('');
      }
      resolve();
    });
  });
}

function initializeDatabase() {
  return new Promise((resolve, reject) => {
    console.log('');
    console.log('🗄️  Initializing database schema...');
    
    // Try to connect and create schema
    const mysql = require('mysql2');
    const db = mysql.createConnection({
      host: 'localhost',
      user: 'root',
      password: '',
      multipleStatements: true
    });
    
    db.connect((err) => {
      if (err) {
        console.log('⚠️  Could not connect to MySQL yet.');
        console.log('   This is expected if MySQL service is not running.');
        console.log('   After MySQL is running, run:');
        console.log('   mysql -u root -p < schema.sql');
        resolve();
        return;
      }
      
      const fs = require('fs');
      const schema = fs.readFileSync('schema.sql', 'utf8');
      
      db.query(schema, (err) => {
        if (err) {
          console.log('⚠️  Schema error:', err.message);
          resolve();
          return;
        }
        console.log('✅ Database "innovashield" created successfully!');
        db.end();
        resolve();
      });
    });
  });
}

async function main() {
  try {
    await downloadInstaller();
    await runInstaller();
    
    console.log('');
    console.log('='.repeat(60));
    console.log('Setup complete!');
    console.log('='.repeat(60));
    console.log('');
    console.log('Next steps:');
    console.log('1. Ensure MySQL service is running (check Windows Services)');
    console.log('2. Initialize schema: mysql -u root -p < schema.sql');
    console.log('3. Start server: npm start');
    console.log('4. Visit: http://localhost:3000');
    console.log('');
  } catch (err) {
    console.error('❌ Error:', err.message);
    console.log('');
    console.log('Alternative: Install MySQL manually from:');
    console.log('https://dev.mysql.com/downloads/mysql/');
  }
}

main();
