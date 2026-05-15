const fs = require('fs');
const path = require('path');

// Look for setup-db.js or schema files
const baseDir = 'C:\\Users\\nicky\\Desktop\\Dec 2026 diary\\InnovaShield';
const files = fs.readdirSync(baseDir);
console.log('Files in project root:', files.join(', '));

// Check for SQL schema files
const sqlFiles = files.filter(f => f.endsWith('.sql') || f.endsWith('.db'));
console.log('SQL/DB files:', sqlFiles.join(', '));

// Read setup-db.js
try {
    const setupContent = fs.readFileSync(path.join(baseDir, 'setup-db.js'), 'utf8');
    console.log('\n=== setup-db.js ===');
    console.log(setupContent.substring(0, 2000));
} catch(e) {
    console.log('No setup-db.js found');
}