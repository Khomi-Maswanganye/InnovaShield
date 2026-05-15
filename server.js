const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const flash = require('connect-flash');
const crypto = require('crypto');
const fs = require('fs');
const PDFDocument = require('pdfkit');
const app = express();
const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));

// ─── LOAD .env (no extra package needed) ─────────────────────────────────────
try {
    fs.readFileSync('.env', 'utf8').split('\n').forEach(line => {
        const [key, ...rest] = line.split('=');
        if (key && key.trim() && !key.trim().startsWith('#') && !(key.trim() in process.env))
            process.env[key.trim()] = rest.join('=').trim();
    });
} catch (_) { /* no .env file — rely on real env vars */ }

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static('public'));

// ─── SESSION & FLASH ──────────────────────────────────────────────────────────
if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET === 'change-me-to-a-long-random-string') {
    console.warn('[WARN] SESSION_SECRET is not set or is default. Set it in .env for production.');
}
app.use(session({
    secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 1000 * 60 * 60 * 8 }
}));
app.use(flash());

app.use((req, res, next) => {
    res.locals.currentUser = req.session.user || null;
    res.locals.flashSuccess = req.flash('success');
    res.locals.flashError = req.flash('error');
    next();
});

// ─── CSRF PROTECTION ─────────────────────────────────────────────────────────
// Simple, no-package implementation: token stored in session, checked on mutating requests.
function generateCsrfToken(req) {
    if (!req.session.csrfToken) req.session.csrfToken = crypto.randomBytes(24).toString('hex');
    return req.session.csrfToken;
}
app.use((req, res, next) => {
    res.locals.csrfToken = generateCsrfToken(req);
    if (['POST','PUT','DELETE','PATCH'].includes(req.method)) {
        const token = req.body._csrf || req.headers['x-csrf-token'];
        if (!token || token !== req.session.csrfToken) {
            return res.status(403).render('error', { message: 'Invalid or missing security token. Please go back and try again.' });
        }
    }
    next();
});

// ─── DATABASE ─────────────────────────────────────────────────────────────────
let dbReady = false;
let dbError = null;

function initDatabase() {
    return new Promise((resolve, reject) => {
        // First connect WITHOUT specifying the database to create it if needed
        const tempDb = mysql.createConnection({
            host: process.env.DB_HOST || 'localhost',
            user: process.env.DB_USER || 'root',
            password: process.env.DB_PASSWORD || ''
        });

        tempDb.connect(async (err) => {
            if (err) {
                dbError = err;
                console.error('❌ MySQL connection failed:', err.message);
                console.error('Ensure MySQL is running. On Windows, start the MySQL service:');
                console.error('  services.msc → MySQL → Start');
                console.error('Or install MySQL: https://dev.mysql.com/downloads/mysql/');
                tempDb.end();
                reject(err);
                return;
            }
            console.log('✅ Connected to MySQL server');

            // Create the database if it doesn't exist
            const dbName = process.env.DB_NAME || 'innovashield';
            try {
                await new Promise((res, rej) => {
                    tempDb.query(`CREATE DATABASE IF NOT EXISTS \`${dbName}\``, (err) => {
                        if (err) rej(err); else res();
                    });
                });
                console.log(`✅ Database "${dbName}" ready`);
            } catch(e) {
                dbError = e;
                console.error('❌ Failed to create database:', e.message);
                tempDb.end();
                reject(e);
                return;
            }

            tempDb.end();

            // Now connect WITH the database
            const db = mysql.createConnection({
                host: process.env.DB_HOST || 'localhost',
                user: process.env.DB_USER || 'root',
                password: process.env.DB_PASSWORD || '',
                database: dbName
            });

            db.connect((err) => {
                if (err) {
                    dbError = err;
                    console.error('❌ Final DB connection failed:', err.message);
                    reject(err);
                    return;
                }
                console.log('✅ Connected to MySQL database!');
                dbReady = true;
                // Attach db to app locals so dbQ can use it
                app.locals.db = db;
                resolve(db);
            });
        });
    });
}

// Start database initialization
initDatabase().then((db) => {
    ensureUsersTable();
}).catch((err) => {
    console.error('⚠️  Database initialization failed. Login/register will still work, but DB-dependent features will show errors.');
});

function dbQ(sql, params = []) {
    return new Promise((resolve, reject) => {
        const db = app.locals.db;
        if (!db) { reject(new Error('Database not initialized')); return; }
        db.query(sql, params, (err, result) => { if (err) reject(err); else resolve(result); });
    });
}

async function ensureUsersTable() {
    try {
        await dbQ(`CREATE TABLE IF NOT EXISTS users (
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
        )`);
        const existing = await dbQ('SELECT COUNT(*) as c FROM users');
        if (existing[0].c === 0) {
            const adminUser = process.env.ADMIN_USERNAME || 'admin';
            const adminEmail = process.env.ADMIN_EMAIL || 'admin@innovashield.com';
            const adminPass = process.env.ADMIN_PASSWORD || 'admin123';
            if (adminPass === 'admin123' || adminPass === 'change-me-on-first-login') {
                console.warn('[WARN] Default admin password is weak. Set ADMIN_PASSWORD in .env before deploying.');
            }
            const hash = await bcrypt.hash(adminPass, 10);
            await dbQ('INSERT INTO users (username, email, password_hash, full_name, role) VALUES (?,?,?,?,?)',
                [adminUser, adminEmail, hash, 'System Administrator', 'Admin']);
            console.log('Default admin created: ' + adminUser + ' (password from ADMIN_PASSWORD env var)');
        }
    } catch(e) { console.error('ensureUsersTable error:', e.message); }
}

// Database readiness middleware — protect routes that need DB, but allow login/register pages and static assets
const dbMiddleware = async (req, res, next) => {
    const allowedWithoutDb = ['/login', '/register', '/public/', '/favicon.ico'];
    if (allowedWithoutDb.some(p => req.path === p || req.path.startsWith(p))) {
        return next();
    }
    if (!dbReady) {
        return res.status(503).render('error', {
            message: 'Database not connected. Ensure MySQL is running and the "innovashield" database exists. Error: ' + (dbError ? dbError.message : 'unknown')
        });
    }
    next();
};
app.use(dbMiddleware);

// ─── AUTH MIDDLEWARE ──────────────────────────────────────────────────────────
function requireLogin(req, res, next) {
    if (!req.session.user) return res.redirect('/login?next=' + encodeURIComponent(req.originalUrl));
    next();
}

function requireRole(...roles) {
    return (req, res, next) => {
        if (!req.session.user) return res.redirect('/login');
        if (!roles.includes(req.session.user.role)) {
            return res.status(403).render('error', { message: 'Access denied. You do not have permission to view this page.' });
        }
        next();
    };
}

function detectIndustry(text) {
    const t = (text || '').toLowerCase();
    if (/health|medical|pharma|drug|bio|clinic|therap|diagnos/.test(t)) return 'Healthcare';
    if (/ai|machine.learn|neural|deep.learn|algorithm|software|compute|digital|cyber|data/.test(t)) return 'Technology';
    if (/energy|solar|wind|battery|fuel|electric|power|renewable/.test(t)) return 'Energy';
    if (/environ|climate|emission|carbon|sustain|recycl/.test(t)) return 'Environment';
    if (/logistic|transport|supply|chain|ship|deliver|freight/.test(t)) return 'Logistics';
    if (/manufactur|robot|automat|assembl|product/.test(t)) return 'Manufacturing';
    if (/agri|farm|crop|seed|fertiliz|harvest/.test(t)) return 'Agriculture';
    if (/financ|bank|crypto|block.?chain|payment|insur/.test(t)) return 'Finance';
    return 'Technology';
}

function toCSV(rows, columns) {
    const header = columns.join(',');
    const body = rows.map(row =>
        columns.map(col => {
            const val = row[col] === null || row[col] === undefined ? '' : String(row[col]);
            return '"' + val.replace(/"/g, '""') + '"';
        }).join(',')
    ).join('\n');
    return header + '\n' + body;
}

// ─── SYNC ─────────────────────────────────────────────────────────────────────
async function syncUSPTO(query) {
    try {
        const url = 'https://api.openalex.org/works?search=' + encodeURIComponent(query) + '&filter=type:article&per_page=25&select=id,doi,title,publication_year,authorships,cited_by_count,primary_location';
        const res = await fetch(url, { headers: { 'Accept': 'application/json', 'User-Agent': 'InnovaShield/1.0' } });
        if (!res.ok) throw new Error('Status ' + res.status);
        const data = await res.json();
        let added = 0;
        for (const p of (data.results || [])) {
            if (!p.title) continue;
            const owner = (p.authorships && p.authorships[0]?.author?.display_name) || 'Unknown';
            const year = p.publication_year || null;
            const filingDate = year ? year + '-01-01' : null;
            const expiryDate = year ? (year + 20) + '-01-01' : null;
            const status = expiryDate && new Date(expiryDate) < new Date() ? 'Expired' : 'Active';
            const patentNumber = p.doi ? p.doi.replace(/^.*\//, '') : p.id.replace('https://openalex.org/', '');
            try {
                await dbQ('INSERT INTO patents (patent_number, title, owner, industry, filing_date, expiry_date, status, description, source) VALUES (?, ?, ?, ?, ?, ?, ?, ?, \'OpenAlex\') ON DUPLICATE KEY UPDATE title=VALUES(title), owner=VALUES(owner), status=VALUES(status)',
                    [patentNumber, p.title, owner, detectIndustry(p.title), filingDate, expiryDate, status, (p.title || '').slice(0, 500)]);
                added++;
            } catch(e) {}
        }
        return added;
    } catch(e) { console.error('[USPTO] Error:', e.message); return 0; }
}

async function syncTrademarks(query) {
    try {
        const url = 'https://api.openalex.org/works?search=' + encodeURIComponent(query) + '&filter=type:article&per_page=25&select=id,title,publication_year,authorships,primary_location';
        const res = await fetch(url, { headers: { 'Accept': 'application/json', 'User-Agent': 'InnovaShield/1.0' } });
        if (!res.ok) throw new Error('Status ' + res.status);
        const data = await res.json();
        let added = 0;
        for (const w of (data.results || [])) {
            if (!w.title) continue;
            const owner = w.authorships?.[0]?.author?.display_name || 'Unknown';
            const year = w.publication_year || new Date().getFullYear();
            const serialNumber = w.id.replace('https://openalex.org/', '');
            const tmNumber = 'TM-' + year + '-' + serialNumber.slice(-6);
            try {
                await dbQ('INSERT INTO trademarks (trademark_number, name, owner, industry, registration_date, expiry_date, status, source) VALUES (?, ?, ?, ?, ?, ?, \'Active\', \'OpenAlex\') ON DUPLICATE KEY UPDATE name=VALUES(name), owner=VALUES(owner)',
                    [tmNumber, w.title.slice(0, 200), owner, detectIndustry(w.title), year + '-01-01', (year + 10) + '-01-01']);
                added++;
            } catch(e) {}
        }
        return added;
    } catch(e) { console.error('[USPTO TM] Error:', e.message); return 0; }
}

let lastSyncTime = null;
let lastSyncCounts = { uspto: 0, trademarks: 0 };

async function runAutoSync(topic) {
    const topics = ['artificial intelligence','machine learning','renewable energy','biotechnology','blockchain','robotics','semiconductor','quantum computing'];
    const t = topic || topics[Math.floor(Math.random() * topics.length)];
    try {
        await dbQ("UPDATE patents SET status='Expired' WHERE expiry_date < CURDATE() AND status='Active'");
        await dbQ("UPDATE trademarks SET status='Expired' WHERE expiry_date < CURDATE() AND status='Active'");
        const u = await syncUSPTO(t);
        const tm = await syncTrademarks(t.split(' ')[0]);
        lastSyncTime = new Date();
        lastSyncCounts = { uspto: u, trademarks: tm };
        return lastSyncCounts;
    } catch(e) { console.error('[AUTO-SYNC] Error:', e.message); return { uspto: 0, trademarks: 0 }; }
}

runAutoSync();
setInterval(() => runAutoSync(), 6 * 60 * 60 * 1000);

// ═══════════════════════════════════════════════════════════════════════════════
// AUTH ROUTES
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/login', (req, res) => {
    if (req.session.user) {
        return res.redirect(req.session.user.role === 'Admin' ? '/admin' : '/');
    }
    res.render('login', { next: req.query.next || '/', errors: req.flash('error') });
});

app.post('/login', async (req, res) => {
     const { username, password } = req.body;
     const errors = [];
     if (!username || !username.trim()) errors.push('Username is required.');
     if (!password) errors.push('Password is required.');
     if (errors.length) return res.render('login', { errors, next: req.body.next || '/' });
     try {
         const rows = await dbQ('SELECT * FROM users WHERE username=? OR email=?', [username.trim(), username.trim()]);
         if (!rows.length) {
             console.warn(`Login attempt for unknown user: ${username.trim()}`);
             return res.render('login', { errors: ['Invalid username or password.'], next: req.body.next || '/' });
         }
         const user = rows[0];
         const match = await bcrypt.compare(password, user.password_hash);
         if (!match) {
             console.warn(`Failed password attempt for user: ${username.trim()}`);
             return res.render('login', { errors: ['Invalid username or password.'], next: req.body.next || '/' });
         }
         await dbQ('UPDATE users SET last_login=NOW() WHERE user_id=?', [user.user_id]);
         req.session.user = { user_id: user.user_id, username: user.username, full_name: user.full_name, role: user.role, email: user.email };
         req.flash('success', 'Welcome back, ' + (user.full_name || user.username) + '!');
         const nextUrl = req.body.next || (user.role === 'Admin' ? '/admin' : '/');
         res.redirect(nextUrl);
     } catch(e) {
         console.error('Login error:', e.message);
         return res.render('login', { errors: ['Login failed: ' + e.message], next: req.body.next || '/' });
     }
 });

app.get('/logout', (req, res) => { req.session.destroy(); res.redirect('/login'); });

app.get('/register', (req, res) => {
    res.render('register', { errors: req.flash('error'), formData: {} });
});

app.post('/register', async (req, res) => {
    // Role is never taken from user input — all self-registered accounts start as Viewer.
    // Admins can promote via /admin/users.
    const { username, email, full_name, password, confirm_password } = req.body;
    const errors = [];
    if (!username || !username.trim()) errors.push('Username is required.');
    else if (username.trim().length < 3) errors.push('Username must be at least 3 characters.');
    else if (username.trim().length > 50) errors.push('Username must be under 50 characters.');
    else if (!/^[a-zA-Z0-9_]+$/.test(username.trim())) errors.push('Username: letters, numbers and underscores only.');
    if (!email || !email.trim()) errors.push('Email is required.');
    else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) errors.push('Please enter a valid email address.');
    if (!password) errors.push('Password is required.');
    else if (password.length < 6) errors.push('Password must be at least 6 characters.');
    else if (password.length > 100) errors.push('Password must be under 100 characters.');
    if (password !== confirm_password) errors.push('Passwords do not match.');
    if (errors.length) return res.render('register', { errors, formData: req.body });
    try {
        const existing = await dbQ('SELECT user_id FROM users WHERE username=? OR email=?', [username.trim(), email.trim()]);
        if (existing.length) return res.render('register', { errors: ['Username or email already exists.'], formData: req.body });
        const hash = await bcrypt.hash(password, 10);
        await dbQ('INSERT INTO users (username, email, password_hash, full_name, role) VALUES (?,?,?,?,?)',
            [username.trim(), email.trim(), hash, (full_name || '').trim(), 'Viewer']);
        req.flash('success', 'Account created! Please log in.');
        res.redirect('/login');
    } catch(e) {
        console.error('Register error:', e);
        res.render('register', { errors: ['An error occurred. Please try again.'], formData: req.body });
    }
});

app.get('/admin', requireLogin, requireRole('Admin'), async (req, res) => {
    try {
        const [patents] = await dbQ('SELECT COUNT(*) as count FROM patents');
        const [trademarks] = await dbQ('SELECT COUNT(*) as count FROM trademarks');
        const [users] = await dbQ('SELECT COUNT(*) as count FROM users');
        const [watchlist] = await dbQ('SELECT COUNT(*) as count FROM watchlist');
        const [expiring] = await dbQ('SELECT COUNT(*) as count FROM patents WHERE expiry_date BETWEEN CURDATE() AND DATE_ADD(CURDATE(), INTERVAL 90 DAY)');
        const [patentActive] = await dbQ('SELECT COUNT(*) as count FROM patents WHERE status="Active"');
        const [patentExpired] = await dbQ('SELECT COUNT(*) as count FROM patents WHERE status="Expired"');
        const [trademarkActive] = await dbQ('SELECT COUNT(*) as count FROM trademarks WHERE status="Active"');
        const [trademarkExpired] = await dbQ('SELECT COUNT(*) as count FROM trademarks WHERE status="Expired"');
        const roles = await dbQ('SELECT role, COUNT(*) as count FROM users GROUP BY role');
        const roleSummary = roles.reduce((acc, row) => { acc[row.role] = row.count; return acc; }, {});

        const now = new Date();
        const defaultFrom = new Date(now.getFullYear(), now.getMonth(), 1).toISOString().split('T')[0];
        const defaultTo = now.toISOString().split('T')[0];
        const dateFrom = req.query.date_from || defaultFrom;
        const dateTo = req.query.date_to || defaultTo;
        const reportType = req.query.report_type || 'all';
        const reportStatus = req.query.status || 'all';

        let reportRows = [];
        let reportSummary = null;
        if (req.query.generate_report === '1') {
            const userRoles = await dbQ('SELECT role, COUNT(*) as count FROM users GROUP BY role');
            const totalUsers = userRoles.reduce((sum, row) => sum + row.count, 0);

            let patentSummary = null;
            let trademarkSummary = null;
            if (reportType === 'all' || reportType === 'patent') {
                const params = [dateFrom + ' 00:00:00', dateTo + ' 23:59:59'];
                const [patentTotal] = await dbQ('SELECT COUNT(*) as count FROM patents WHERE created_at BETWEEN ? AND ?', params);
                const [patentActive] = await dbQ('SELECT COUNT(*) as count FROM patents WHERE created_at BETWEEN ? AND ? AND status="Active"', params);
                const [patentExpired] = await dbQ('SELECT COUNT(*) as count FROM patents WHERE created_at BETWEEN ? AND ? AND status="Expired"', params);
                const [patentExpiring] = await dbQ('SELECT COUNT(*) as count FROM patents WHERE expiry_date BETWEEN CURDATE() AND DATE_ADD(CURDATE(), INTERVAL 90 DAY) AND status="Active"');
                patentSummary = {
                    total: patentTotal.count,
                    active: patentActive.count,
                    expired: patentExpired.count,
                    expiringSoon: patentExpiring.count
                };
            }
            if (reportType === 'all' || reportType === 'trademark') {
                const params = [dateFrom + ' 00:00:00', dateTo + ' 23:59:59'];
                const [trademarkTotal] = await dbQ('SELECT COUNT(*) as count FROM trademarks WHERE created_at BETWEEN ? AND ?', params);
                const [trademarkActive] = await dbQ('SELECT COUNT(*) as count FROM trademarks WHERE created_at BETWEEN ? AND ? AND status="Active"', params);
                const [trademarkExpired] = await dbQ('SELECT COUNT(*) as count FROM trademarks WHERE created_at BETWEEN ? AND ? AND status="Expired"', params);
                const [trademarkExpiring] = await dbQ('SELECT COUNT(*) as count FROM trademarks WHERE expiry_date BETWEEN CURDATE() AND DATE_ADD(CURDATE(), INTERVAL 90 DAY) AND status="Active"');
                trademarkSummary = {
                    total: trademarkTotal.count,
                    active: trademarkActive.count,
                    expired: trademarkExpired.count,
                    expiringSoon: trademarkExpiring.count
                };
            }
            reportSummary = {
                generatedBy: req.session.user.full_name || req.session.user.username,
                generatedOn: new Date().toLocaleString(),
                dateFrom,
                dateTo,
                reportType,
                reportStatus,
                userCount: totalUsers,
                userRoles,
                patentSummary,
                trademarkSummary,
                rowCount: (patentSummary ? patentSummary.total : 0) + (trademarkSummary ? trademarkSummary.total : 0)
            };
        }

        const stats = {
            totalPatents: patents.count,
            totalTrademarks: trademarks.count,
            totalUsers: users.count,
            activeWatchlist: watchlist.count,
            expiringSoon: expiring.count,
            lastSync: lastSyncTime ? Math.floor((Date.now() - new Date(lastSyncTime)) / (1000 * 60 * 60 * 24)) : 'Never',
            patentActive: patentActive.count,
            patentExpired: patentExpired.count,
            trademarkActive: trademarkActive.count,
            trademarkExpired: trademarkExpired.count,
            roleSummary
        };

        res.render('admin', {
            stats,
            lastSyncTime,
            reportRows,
            reportSummary,
            reportFilters: { dateFrom, dateTo, reportType, reportStatus, defaultFrom, defaultTo },
            adminName: req.session.user.full_name || req.session.user.username
        });
    } catch(e) { res.render('error', { message: 'Could not load dashboard.' }); }
});

app.get('/admin/report/export/csv', requireLogin, requireRole('Admin'), async (req, res) => {
    try {
        const dateFrom = req.query.date_from || new Date(new Date().getFullYear(), new Date().getMonth(), 1).toISOString().split('T')[0];
        const dateTo = req.query.date_to || new Date().toISOString().split('T')[0];
        const reportType = req.query.report_type || 'all';
        const reportStatus = req.query.status || 'all';

        const userRoles = await dbQ('SELECT role, COUNT(*) as count FROM users GROUP BY role');
        const totalUsers = userRoles.reduce((sum, row) => sum + row.count, 0);
        const summaryRows = [{ section: 'Users', metric: 'total_users', value: totalUsers }];
        userRoles.forEach(role => summaryRows.push({ section: 'Users', metric: `role_${role.role.toLowerCase()}`, value: role.count }));

        if (reportType === 'all' || reportType === 'patent') {
            const params = [dateFrom + ' 00:00:00', dateTo + ' 23:59:59'];
            const [patentTotal] = await dbQ('SELECT COUNT(*) as count FROM patents WHERE created_at BETWEEN ? AND ?', params);
            const [patentActive] = await dbQ('SELECT COUNT(*) as count FROM patents WHERE created_at BETWEEN ? AND ? AND status="Active"', params);
            const [patentExpired] = await dbQ('SELECT COUNT(*) as count FROM patents WHERE created_at BETWEEN ? AND ? AND status="Expired"', params);
            const [patentExpiring] = await dbQ('SELECT COUNT(*) as count FROM patents WHERE expiry_date BETWEEN CURDATE() AND DATE_ADD(CURDATE(), INTERVAL 90 DAY) AND status="Active"');
            summaryRows.push({ section: 'Patents', metric: 'total', value: patentTotal.count });
            summaryRows.push({ section: 'Patents', metric: 'active', value: patentActive.count });
            summaryRows.push({ section: 'Patents', metric: 'expired', value: patentExpired.count });
            summaryRows.push({ section: 'Patents', metric: 'expiring_soon', value: patentExpiring.count });
        }
        if (reportType === 'all' || reportType === 'trademark') {
            const params = [dateFrom + ' 00:00:00', dateTo + ' 23:59:59'];
            const [tmTotal] = await dbQ('SELECT COUNT(*) as count FROM trademarks WHERE created_at BETWEEN ? AND ?', params);
            const [tmActive] = await dbQ('SELECT COUNT(*) as count FROM trademarks WHERE created_at BETWEEN ? AND ? AND status="Active"', params);
            const [tmExpired] = await dbQ('SELECT COUNT(*) as count FROM trademarks WHERE created_at BETWEEN ? AND ? AND status="Expired"', params);
            const [tmExpiring] = await dbQ('SELECT COUNT(*) as count FROM trademarks WHERE expiry_date BETWEEN CURDATE() AND DATE_ADD(CURDATE(), INTERVAL 90 DAY) AND status="Active"');
            summaryRows.push({ section: 'Trademarks', metric: 'total', value: tmTotal.count });
            summaryRows.push({ section: 'Trademarks', metric: 'active', value: tmActive.count });
            summaryRows.push({ section: 'Trademarks', metric: 'expired', value: tmExpired.count });
            summaryRows.push({ section: 'Trademarks', metric: 'expiring_soon', value: tmExpiring.count });
        }
        const csv = toCSV(summaryRows, ['section','metric','value']);
        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', 'attachment; filename="admin-report.csv"');
        res.send(csv);
    } catch(e) { console.error(e); res.status(500).send('Export failed'); }
});

app.get('/admin/report/export/pdf', requireLogin, requireRole('Admin'), async (req, res) => {
    try {
        const dateFrom = req.query.date_from || new Date(new Date().getFullYear(), new Date().getMonth(), 1).toISOString().split('T')[0];
        const dateTo = req.query.date_to || new Date().toISOString().split('T')[0];
        const reportType = req.query.report_type || 'all';
        const reportStatus = req.query.status || 'all';

        const userRoles = await dbQ('SELECT role, COUNT(*) as count FROM users GROUP BY role');
        const totalUsers = userRoles.reduce((sum, row) => sum + row.count, 0);

        const patentSummary = reportType === 'all' || reportType === 'patent' ? await (async () => {
            const params = [dateFrom + ' 00:00:00', dateTo + ' 23:59:59'];
            const [total] = await dbQ('SELECT COUNT(*) as count FROM patents WHERE created_at BETWEEN ? AND ?', params);
            const [active] = await dbQ('SELECT COUNT(*) as count FROM patents WHERE created_at BETWEEN ? AND ? AND status="Active"', params);
            const [expired] = await dbQ('SELECT COUNT(*) as count FROM patents WHERE created_at BETWEEN ? AND ? AND status="Expired"', params);
            const [expiring] = await dbQ('SELECT COUNT(*) as count FROM patents WHERE expiry_date BETWEEN CURDATE() AND DATE_ADD(CURDATE(), INTERVAL 90 DAY) AND status="Active"');
            return { total: total.count, active: active.count, expired: expired.count, expiringSoon: expiring.count };
        })() : null;
        const trademarkSummary = reportType === 'all' || reportType === 'trademark' ? await (async () => {
            const params = [dateFrom + ' 00:00:00', dateTo + ' 23:59:59'];
            const [total] = await dbQ('SELECT COUNT(*) as count FROM trademarks WHERE created_at BETWEEN ? AND ?', params);
            const [active] = await dbQ('SELECT COUNT(*) as count FROM trademarks WHERE created_at BETWEEN ? AND ? AND status="Active"', params);
            const [expired] = await dbQ('SELECT COUNT(*) as count FROM trademarks WHERE created_at BETWEEN ? AND ? AND status="Expired"', params);
            const [expiring] = await dbQ('SELECT COUNT(*) as count FROM trademarks WHERE expiry_date BETWEEN CURDATE() AND DATE_ADD(CURDATE(), INTERVAL 90 DAY) AND status="Active"');
            return { total: total.count, active: active.count, expired: expired.count, expiringSoon: expiring.count };
        })() : null;

        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', 'attachment; filename="admin-report.pdf"');
        const doc = new PDFDocument({ size: 'A4', margin: 50 });
        doc.pipe(res);
        doc.fontSize(18).text('Admin Report', { underline: true });
        doc.moveDown();
        doc.fontSize(12).text(`Generated by: ${req.session.user.full_name || req.session.user.username}`);
        doc.text(`Date range: ${dateFrom} to ${dateTo}`);
        doc.text(`Type: ${reportType}`);
        doc.text(`Status: ${reportStatus}`);
        doc.text(`Total Users: ${totalUsers}`);
        userRoles.forEach(role => {
            doc.text(`  ${role.role}: ${role.count}`);
        });
        doc.moveDown();
        if (patentSummary) {
            doc.fontSize(14).text('Patent Summary');
            doc.fontSize(12).text(`  Total: ${patentSummary.total}`);
            doc.text(`  Active: ${patentSummary.active}`);
            doc.text(`  Expired: ${patentSummary.expired}`);
            doc.text(`  Expiring Soon: ${patentSummary.expiringSoon}`);
            doc.moveDown();
        }
        if (trademarkSummary) {
            doc.fontSize(14).text('Trademark Summary');
            doc.fontSize(12).text(`  Total: ${trademarkSummary.total}`);
            doc.text(`  Active: ${trademarkSummary.active}`);
            doc.text(`  Expired: ${trademarkSummary.expired}`);
            doc.text(`  Expiring Soon: ${trademarkSummary.expiringSoon}`);
            doc.moveDown();
        }
        doc.end();
    } catch(e) { console.error(e); res.status(500).send('Export failed'); }
});

app.get('/admin/users', requireLogin, requireRole('Admin'), async (req, res) => {
    try {
        const users = await dbQ('SELECT user_id, username, email, full_name, role, created_at, last_login FROM users ORDER BY created_at DESC');
        res.render('admin_users', { users });
    } catch(e) { res.render('error', { message: 'Could not load users.' }); }
});

app.post('/admin/users/delete/:id', requireLogin, requireRole('Admin'), async (req, res) => {
    try {
        if (parseInt(req.params.id) === req.session.user.user_id) {
            req.flash('error', 'You cannot delete your own account.');
            return res.redirect('/admin/users');
        }
        await dbQ('DELETE FROM users WHERE user_id=?', [req.params.id]);
        req.flash('success', 'User deleted.');
        res.redirect('/admin/users');
    } catch(e) { req.flash('error', 'Could not delete user.'); res.redirect('/admin/users'); }
});

app.post('/admin/users/role/:id', requireLogin, requireRole('Admin'), async (req, res) => {
    try {
        if (!['Admin','Analyst','Viewer'].includes(req.body.role)) {
            req.flash('error', 'Invalid role.'); return res.redirect('/admin/users');
        }
        await dbQ('UPDATE users SET role=? WHERE user_id=?', [req.body.role, req.params.id]);
        req.flash('success', 'User role updated.');
        res.redirect('/admin/users');
    } catch(e) { req.flash('error', 'Could not update role.'); res.redirect('/admin/users'); }
});

// ═══════════════════════════════════════════════════════════════════════════════
// MAIN ROUTES
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/', async (req, res) => {
    const query = req.query.q || '';
    const industry = req.query.industry || '';
    const searchType = req.query.type || 'both';
    const sortBy = req.query.sort || 'patent_id';
    const validSorts = ['patent_id','expiry_date','filing_date','owner','title','patent_number','industry','status'];
    const orderBy = validSorts.includes(sortBy) ? sortBy : 'patent_id';
    if (query) {
        const topic = query.split(' ')[0];
        if (searchType !== 'trademarks') syncUSPTO(topic).catch(() => {});
        if (searchType !== 'patents') syncTrademarks(topic).catch(() => {});
    }
    try {
        const industries = await dbQ('SELECT DISTINCT industry FROM patents WHERE industry IS NOT NULL');
        const [p, t, a, ex] = await Promise.all([
            dbQ('SELECT COUNT(*) as c FROM patents'),
            dbQ('SELECT COUNT(*) as c FROM trademarks'),
            dbQ('SELECT COUNT(*) as c FROM patents WHERE status="Active"'),
            dbQ('SELECT COUNT(*) as c FROM patents WHERE expiry_date BETWEEN CURDATE() AND DATE_ADD(CURDATE(), INTERVAL 90 DAY) AND status="Active"')
        ]);
        const stats = { patents: p[0].c, trademarks: t[0].c, active: a[0].c, expiring: ex[0].c };
        if (!query && !industry) return res.render('index', { results: [], query: '', industry: '', searchType, sortBy, industries, stats, lastSyncTime, lastSyncCounts });
        const pParams = [], tmParams = [];
        let patentSql = "SELECT *, 'Patent' as record_type, patent_number as display_number, title as display_title FROM patents WHERE 1=1";
        let tmSql = "SELECT *, 'Trademark' as record_type, trademark_number as display_number, name as display_title, NULL as filing_date FROM trademarks WHERE 1=1";
        if (query) {
            patentSql += ' AND (title LIKE ? OR owner LIKE ? OR industry LIKE ? OR patent_number LIKE ?)';
            pParams.push('%'+query+'%','%'+query+'%','%'+query+'%','%'+query+'%');
            tmSql += ' AND (name LIKE ? OR owner LIKE ? OR industry LIKE ? OR trademark_number LIKE ?)';
            tmParams.push('%'+query+'%','%'+query+'%','%'+query+'%','%'+query+'%');
        }
        if (industry) { patentSql += ' AND industry=?'; pParams.push(industry); tmSql += ' AND industry=?'; tmParams.push(industry); }
        const patents = searchType !== 'trademarks' ? await dbQ(patentSql, pParams) : [];
        const tms = searchType !== 'patents' ? await dbQ(tmSql, tmParams) : [];
        const results = [...patents, ...tms].sort((a, b) => (a[orderBy] > b[orderBy]) ? 1 : -1);
        res.render('index', { results, query, industry, searchType, sortBy, industries, stats, lastSyncTime, lastSyncCounts });
    } catch(e) { console.error(e); res.render('error', { message: 'Database error.' }); }
});

// ─── PATENTS ──────────────────────────────────────────────────────────────────
app.get('/patents', requireLogin, requireRole('Admin', 'Analyst'), async (req, res) => {
    const search = req.query.q || '';
    const source = req.query.source || '';
    const statusFilter = req.query.status || '';
    const industryFilter = req.query.industry || '';
    const now = new Date();
    const defaultFrom = now.getFullYear() + '-' + String(now.getMonth()+1).padStart(2,'0') + '-01';
    const dateFrom = req.query.date_from || defaultFrom;
    const dateTo = req.query.date_to || '';
    if (search) syncUSPTO(search.split(' ')[0]).catch(() => {});
    try {
        let sql = 'SELECT * FROM patents WHERE 1=1';
        const p = [];
        if (search) { sql += ' AND (title LIKE ? OR owner LIKE ? OR patent_number LIKE ?)'; p.push('%'+search+'%','%'+search+'%','%'+search+'%'); }
        if (source) { sql += ' AND source=?'; p.push(source); }
        if (statusFilter) { sql += ' AND status=?'; p.push(statusFilter); }
        if (industryFilter) { sql += ' AND industry=?'; p.push(industryFilter); }
        if (dateFrom) { sql += ' AND (filing_date >= ? OR filing_date IS NULL)'; p.push(dateFrom); }
        if (dateTo) { sql += ' AND filing_date <= ?'; p.push(dateTo); }
        sql += ' ORDER BY filing_date DESC';
        const patents = await dbQ(sql, p);
        const sourceCounts = await dbQ('SELECT source, COUNT(*) as c FROM patents GROUP BY source');
        const activeCount = (await dbQ('SELECT COUNT(*) as c FROM patents WHERE status="Active"'))[0].c;
        const industries = await dbQ('SELECT DISTINCT industry FROM patents WHERE industry IS NOT NULL ORDER BY industry');
        res.render('patents', { patents, search, source, statusFilter, industryFilter, dateFrom, dateTo, defaultFrom, sourceCounts, activeCount, industries, success: req.query.success, lastSyncTime, lastSyncCounts });
    } catch(e) { console.error(e); res.render('error', { message: 'Database error loading patents.' }); }
});

app.get('/patents/export/csv', requireLogin, requireRole('Admin', 'Analyst'), async (req, res) => {
    try {
        const rows = await dbQ('SELECT patent_number, title, owner, industry, filing_date, expiry_date, status, source FROM patents ORDER BY filing_date DESC');
        const csv = toCSV(rows, ['patent_number','title','owner','industry','filing_date','expiry_date','status','source']);
        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', 'attachment; filename="patents.csv"');
        res.send(csv);
    } catch(e) { res.status(500).send('Export failed'); }
});

app.post('/patents/delete/:id', requireLogin, requireRole('Admin','Analyst'), async (req, res) => {
    try { await dbQ('DELETE FROM patents WHERE patent_id=?', [req.params.id]); res.redirect('/patents?success=deleted'); }
    catch(e) { res.redirect('/patents'); }
});

// ─── TRADEMARKS ───────────────────────────────────────────────────────────────
app.get('/trademarks', requireLogin, requireRole('Admin', 'Analyst'), async (req, res) => {
    const search = req.query.q || '';
    const source = req.query.source || '';
    const statusFilter = req.query.status || '';
    const now = new Date();
    const defaultFrom = now.getFullYear() + '-' + String(now.getMonth()+1).padStart(2,'0') + '-01';
    const dateFrom = req.query.date_from || defaultFrom;
    const dateTo = req.query.date_to || '';
    if (search) syncTrademarks(search.split(' ')[0]).catch(() => {});
    try {
        let sql = 'SELECT * FROM trademarks WHERE 1=1';
        const p = [];
        if (search) { sql += ' AND (name LIKE ? OR owner LIKE ? OR trademark_number LIKE ?)'; p.push('%'+search+'%','%'+search+'%','%'+search+'%'); }
        if (source) { sql += ' AND source=?'; p.push(source); }
        if (statusFilter) { sql += ' AND status=?'; p.push(statusFilter); }
        if (dateFrom) { sql += ' AND (registration_date >= ? OR registration_date IS NULL)'; p.push(dateFrom); }
        if (dateTo) { sql += ' AND registration_date <= ?'; p.push(dateTo); }
        sql += ' ORDER BY registration_date DESC';
        const trademarks = await dbQ(sql, p);
        res.render('trademarks', { trademarks, search, source, statusFilter, dateFrom, dateTo, defaultFrom, success: req.query.success, lastSyncTime, lastSyncCounts });
    } catch(e) { console.error(e); res.render('error', { message: 'Database error loading trademarks.' }); }
});

app.get('/trademarks/export/csv', requireLogin, requireRole('Admin', 'Analyst'), async (req, res) => {
    try {
        const rows = await dbQ('SELECT trademark_number, name, owner, industry, registration_date, expiry_date, status, source FROM trademarks ORDER BY registration_date DESC');
        const csv = toCSV(rows, ['trademark_number','name','owner','industry','registration_date','expiry_date','status','source']);
        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', 'attachment; filename="trademarks.csv"');
        res.send(csv);
    } catch(e) { res.status(500).send('Export failed'); }
});

app.post('/trademarks/delete/:id', requireLogin, requireRole('Admin','Analyst'), async (req, res) => {
    try { await dbQ('DELETE FROM trademarks WHERE trademark_id=?', [req.params.id]); res.redirect('/trademarks?success=deleted'); }
    catch(e) { res.redirect('/trademarks'); }
});

// ─── WATCHLIST ────────────────────────────────────────────────────────────────
app.get('/watchlist', async (req, res) => {
    try {
        if (!req.session.guestWatchlist) req.session.guestWatchlist = [];
        let watchlist = [];
        const allPatents = await dbQ('SELECT * FROM patents ORDER BY title');
        const allTrademarks = await dbQ('SELECT * FROM trademarks ORDER BY name');

        if (req.session.user) {
            const isAdmin = req.session.user.role === 'Admin';
            let wSql = 'SELECT w.*, p.title as patent_title, p.owner as patent_owner, p.status as patent_status, p.expiry_date as patent_expiry, p.patent_number, t.name as trademark_title, t.owner as trademark_owner, t.status as trademark_status, t.expiry_date as trademark_expiry, t.trademark_number FROM watchlist w LEFT JOIN patents p ON w.patent_id=p.patent_id LEFT JOIN trademarks t ON w.trademark_id=t.trademark_id';
            const wParams = [];
            if (!isAdmin) { wSql += ' WHERE w.user_id=?'; wParams.push(req.session.user.username); }
            wSql += ' ORDER BY w.watchlist_id DESC';
            watchlist = await dbQ(wSql, wParams);
        } else {
            watchlist = req.session.guestWatchlist.map((item, index) => {
                const patent = allPatents.find(p => String(p.patent_id) === String(item.patent_id));
                const trademark = allTrademarks.find(t => String(t.trademark_id) === String(item.trademark_id));
                return {
                    display_id: 'G-' + String(index + 1).padStart(3, '0'),
                    patent_id: item.patent_id || null,
                    trademark_id: item.trademark_id || null,
                    patent_title: patent ? patent.title : null,
                    patent_owner: patent ? patent.owner : null,
                    patent_status: patent ? patent.status : null,
                    patent_expiry: patent ? patent.expiry_date : null,
                    patent_number: patent ? patent.patent_number : null,
                    trademark_title: trademark ? trademark.name : null,
                    trademark_owner: trademark ? trademark.owner : null,
                    trademark_status: trademark ? trademark.status : null,
                    trademark_expiry: trademark ? trademark.expiry_date : null,
                    trademark_number: trademark ? trademark.trademark_number : null,
                    user_id: item.user_id || 'Anonymous',
                    notes: item.notes || '-',
                    created_at: item.created_at,
                    demo: true
                };
            });
        }

        res.render('watchlist', {
            watchlist,
            patents: allPatents,
            trademarks: allTrademarks,
            success: req.query.success,
            editItem: null,
            isAuthenticated: !!req.session.user,
            guestCount: req.session.guestWatchlist.length
        });
    } catch(e) { console.error(e); res.render('error', { message: 'Could not load watchlist.' }); }
});

app.post('/watchlist/add', async (req, res) => {
    const { type, patent_id, trademark_id, notes, user_id } = req.body;
    const errors = [];
    if (!['patent','trademark'].includes(type)) errors.push('Invalid type.');
    if (type === 'patent' && (!patent_id || !patent_id.trim())) errors.push('Please select a patent.');
    if (type === 'trademark' && (!trademark_id || !trademark_id.trim())) errors.push('Please select a trademark.');
    if (notes && notes.length > 1000) errors.push('Notes must be under 1000 characters.');
    if (errors.length) { req.flash('error', errors.join(' ')); return res.redirect('/watchlist'); }
    try {
        if (!req.session.user) {
            if (!req.session.guestWatchlist) req.session.guestWatchlist = [];
            if (req.session.guestWatchlist.length >= 5) {
                req.flash('error', 'Anonymous watchlist is limited to 5 items. Please register or log in to add more.');
                return res.redirect('/watchlist');
            }
            req.session.guestWatchlist.push({
                type,
                patent_id: type === 'patent' ? patent_id : null,
                trademark_id: type === 'trademark' ? trademark_id : null,
                notes: notes || null,
                user_id: user_id ? user_id.trim() : 'Anonymous',
                created_at: new Date().toISOString()
            });
            return res.redirect('/watchlist?success=added');
        }

        await dbQ('INSERT INTO watchlist (patent_id, trademark_id, user_id, notes) VALUES (?,?,?,?)',
            [type === 'patent' ? patent_id : null, type === 'trademark' ? trademark_id : null, req.session.user.username, notes || null]);
        res.redirect('/watchlist?success=added');
    } catch(e) { req.flash('error', 'Could not add to watchlist.'); res.redirect('/watchlist'); }
});

app.get('/watchlist/edit/:id', requireLogin, async (req, res) => {
    try {
        const rows = await dbQ('SELECT * FROM watchlist WHERE watchlist_id=?', [req.params.id]);
        if (!rows.length) return res.redirect('/watchlist');
        const item = rows[0];
        if (req.session.user.role !== 'Admin' && item.user_id !== req.session.user.username) {
            return res.status(403).render('error', { message: 'You can only edit your own watchlist items.' });
        }
        const allPatents = await dbQ('SELECT * FROM patents ORDER BY title');
        const allTrademarks = await dbQ('SELECT * FROM trademarks ORDER BY name');
        const watchlist = await dbQ('SELECT w.*, p.title as patent_title, t.name as trademark_title FROM watchlist w LEFT JOIN patents p ON w.patent_id=p.patent_id LEFT JOIN trademarks t ON w.trademark_id=t.trademark_id ORDER BY w.watchlist_id DESC');
        res.render('watchlist', { watchlist, patents: allPatents, trademarks: allTrademarks, success: null, editItem: item });
    } catch(e) { res.redirect('/watchlist'); }
});

app.post('/watchlist/update', requireLogin, async (req, res) => {
    const { watchlist_id, type, patent_id, trademark_id, notes } = req.body;
    const errors = [];
    if (!watchlist_id || isNaN(parseInt(watchlist_id))) errors.push('Invalid watchlist item.');
    if (type === 'patent' && (!patent_id || !patent_id.trim())) errors.push('Please select a patent.');
    if (type === 'trademark' && (!trademark_id || !trademark_id.trim())) errors.push('Please select a trademark.');
    if (notes && notes.length > 1000) errors.push('Notes must be under 1000 characters.');
    if (errors.length) { req.flash('error', errors.join(' ')); return res.redirect('/watchlist'); }
    try {
        const rows = await dbQ('SELECT * FROM watchlist WHERE watchlist_id=?', [watchlist_id]);
        if (!rows.length) return res.redirect('/watchlist');
        if (req.session.user.role !== 'Admin' && rows[0].user_id !== req.session.user.username) {
            return res.status(403).render('error', { message: 'Access denied.' });
        }
        await dbQ('UPDATE watchlist SET patent_id=?, trademark_id=?, notes=? WHERE watchlist_id=?',
            [type === 'patent' ? patent_id : null, type === 'trademark' ? trademark_id : null, notes || null, watchlist_id]);
        res.redirect('/watchlist?success=updated');
    } catch(e) { req.flash('error', 'Could not update.'); res.redirect('/watchlist'); }
});

app.post('/watchlist/delete/:id', requireLogin, async (req, res) => {
    try {
        const rows = await dbQ('SELECT * FROM watchlist WHERE watchlist_id=?', [req.params.id]);
        if (!rows.length) return res.redirect('/watchlist');
        if (req.session.user.role !== 'Admin' && rows[0].user_id !== req.session.user.username) {
            return res.status(403).render('error', { message: 'Access denied.' });
        }
        await dbQ('DELETE FROM watchlist WHERE watchlist_id=?', [req.params.id]);
        res.redirect('/watchlist?success=deleted');
    } catch(e) { req.flash('error', 'Could not remove.'); res.redirect('/watchlist'); }
});

app.get('/watchlist/export/csv', requireLogin, async (req, res) => {
    try {
        const isAdmin = req.session.user.role === 'Admin';
        let sql = 'SELECT w.watchlist_id, w.user_id, w.notes, w.created_at, p.patent_number, p.title as patent_title, p.owner as patent_owner, t.trademark_number, t.name as trademark_name, t.owner as trademark_owner FROM watchlist w LEFT JOIN patents p ON w.patent_id=p.patent_id LEFT JOIN trademarks t ON w.trademark_id=t.trademark_id';
        const params = [];
        if (!isAdmin) { sql += ' WHERE w.user_id=?'; params.push(req.session.user.username); }
        const rows = await dbQ(sql, params);
        const csv = toCSV(rows, ['watchlist_id','user_id','notes','created_at','patent_number','patent_title','patent_owner','trademark_number','trademark_name','trademark_owner']);
        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', 'attachment; filename="watchlist.csv"');
        res.send(csv);
    } catch(e) { res.status(500).send('Export failed'); }
});

// ─── EXPIRING ─────────────────────────────────────────────────────────────────
app.get('/expiring', requireLogin, async (req, res) => {
    const now = new Date();
    const defaultFrom = now.toISOString().split('T')[0];
    const defaultTo = new Date(now.getTime() + 180*24*60*60*1000).toISOString().split('T')[0];
    const dateFrom = req.query.date_from || defaultFrom;
    const dateTo = req.query.date_to || defaultTo;
    try {
        const patents = await dbQ("SELECT * FROM patents WHERE expiry_date BETWEEN ? AND ? AND status='Active' ORDER BY expiry_date ASC", [dateFrom, dateTo]);
        const trademarks = await dbQ("SELECT * FROM trademarks WHERE expiry_date BETWEEN ? AND ? AND status='Active' ORDER BY expiry_date ASC", [dateFrom, dateTo]);
        res.render('expiring', { patents, trademarks, dateFrom, dateTo, defaultFrom, defaultTo });
    } catch(e) { res.render('error', { message: 'Could not load expiring records.' }); }
});

app.get('/expiring/export/csv', requireLogin, async (req, res) => {
    try {
        const now = new Date();
        const defaultTo = new Date(now.getTime() + 180*24*60*60*1000).toISOString().split('T')[0];
        const dateFrom = req.query.date_from || now.toISOString().split('T')[0];
        const dateTo = req.query.date_to || defaultTo;
        const patents = await dbQ("SELECT 'Patent' as type, patent_number as number, title as name, owner, industry, expiry_date, status FROM patents WHERE expiry_date BETWEEN ? AND ? AND status='Active' ORDER BY expiry_date", [dateFrom, dateTo]);
        const tms = await dbQ("SELECT 'Trademark' as type, trademark_number as number, name, owner, industry, expiry_date, status FROM trademarks WHERE expiry_date BETWEEN ? AND ? AND status='Active' ORDER BY expiry_date", [dateFrom, dateTo]);
        const csv = toCSV([...patents, ...tms], ['type','number','name','owner','industry','expiry_date','status']);
        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', 'attachment; filename="expiring.csv"');
        res.send(csv);
    } catch(e) { res.status(500).send('Export failed'); }
});

// ─── ALERTS ───────────────────────────────────────────────────────────────────
app.get('/alerts', requireLogin, async (req, res) => {
    try {
        const alerts = await dbQ("SELECT * FROM trademarks WHERE status IN ('Renewed','Updated','Pending') ORDER BY trademark_id DESC");
        const changes = await dbQ('SELECT * FROM ownership_changes ORDER BY change_date DESC LIMIT 10').catch(() => []);
        res.render('alerts', { alerts, changes });
    } catch(e) { res.render('error', { message: 'Could not load alerts.' }); }
});

// ─── TRENDS ───────────────────────────────────────────────────────────────────
app.get('/trends', requireLogin, async (req, res) => {
    try {
        const industryStats = await dbQ('SELECT industry, COUNT(*) as count FROM patents WHERE industry IS NOT NULL GROUP BY industry ORDER BY count DESC');
        const topOwners = await dbQ('SELECT owner, COUNT(*) as count FROM patents WHERE owner IS NOT NULL AND owner!="Unknown" GROUP BY owner ORDER BY count DESC LIMIT 10');
        const statusStats = await dbQ('SELECT status, COUNT(*) as total FROM patents GROUP BY status');
        res.render('trends', { industryStats, topOwners, statusStats });
    } catch(e) { res.render('error', { message: 'Could not load trends.' }); }
});

app.get('/trends/export/csv', requireLogin, async (req, res) => {
    try {
        const rows = await dbQ('SELECT industry, COUNT(*) as patent_count FROM patents WHERE industry IS NOT NULL GROUP BY industry ORDER BY patent_count DESC');
        const csv = toCSV(rows, ['industry','patent_count']);
        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', 'attachment; filename="trends.csv"');
        res.send(csv);
    } catch(e) { res.status(500).send('Export failed'); }
});

// ─── PRICING & API ────────────────────────────────────────────────────────────
app.get('/pricing', (req, res) => { res.render('pricing'); });

app.post('/api/ai-insights', requireLogin, async (req, res) => {
    const { industryStats, topOwners } = req.body;
    try {
        const response = await fetch('https://api.anthropic.com/v1/messages', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                model: 'claude-sonnet-4-20250514', max_tokens: 1500,
                messages: [{ role: 'user', content: 'You are an IP intelligence analyst. Based on this patent database data:\nIndustries: ' + JSON.stringify(industryStats) + '\nTop owners: ' + JSON.stringify(topOwners) + '\n\nGenerate a JSON response with exactly this structure (no markdown, pure JSON):\n{"news":[{"title":"headline","summary":"2 sentences","impact":"effect","tag":"Legal|Tech|Market"}],"opportunities":[{"title":"title","description":"2 sentences","industry":"name","potential":"High|Medium|Low"}],"market_signals":[{"signal":"one line","direction":"up|down|neutral"}]}' }]
            })
        });
        const data = await response.json();
        const clean = data.content[0].text.replace(/```json|```/g, '').trim();
        res.json(JSON.parse(clean));
    } catch(e) { res.status(500).json({ error: 'AI error' }); }
});

app.post('/api/sync', requireLogin, requireRole('Admin','Analyst'), async (req, res) => {
    const counts = await runAutoSync(req.body.topic || 'artificial intelligence');
    res.json({ success: true, synced: counts, time: new Date() });
});

app.get('/api/sync-status', requireLogin, async (req, res) => {
    try {
        const sources = await dbQ('SELECT source, COUNT(*) as c FROM patents GROUP BY source');
        const tCount = await dbQ('SELECT COUNT(*) as c FROM trademarks');
        res.json({ sources, trademarks: tCount[0].c, lastSyncTime, lastSyncCounts });
    } catch(e) { res.status(500).json({ error: 'DB error' }); }
});

app.get('/api/patents', requireLogin, requireRole('Admin'), async (req, res) => {
    try { const r = await dbQ('SELECT * FROM patents'); res.json({ success: true, count: r.length, data: r }); }
    catch(e) { res.status(500).json({ error: 'DB error' }); }
});

app.get('/api/trademarks', requireLogin, requireRole('Admin'), async (req, res) => {
    try { const r = await dbQ('SELECT * FROM trademarks'); res.json({ success: true, count: r.length, data: r }); }
    catch(e) { res.status(500).json({ error: 'DB error' }); }
});

app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).render('error', { message: 'An unexpected error occurred. Please try again.' });
});

app.listen(3000, () => { console.log('Server running on http://localhost:3000'); });