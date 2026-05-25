// config/database.js
// Week 4/5: SQLite database using ONLY prepared statements (no SQL injection possible)
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const { logger } = require('./logger');

const db = new sqlite3.Database(path.join(__dirname, '../database.db'), err => {
  if (err) { logger.error('DB failed', { error: err.message }); process.exit(1); }
  logger.info('Database connected');
});

// Create tables on startup
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    email    TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role     TEXT DEFAULT 'user',
    created  DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS audit_log (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id   INTEGER,
    action    TEXT,
    ip        TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Seed an admin user (password: Admin@2026)
  const bcrypt = require('bcryptjs');
  const hash = bcrypt.hashSync('Admin@2026', 12);
  db.run(`INSERT OR IGNORE INTO users (email, password, role) VALUES (?, ?, ?)`,
    ['admin@dhc.com', hash, 'admin']);
  logger.info('Admin user seeded: admin@dhc.com / Admin@2026');
});

// All queries use ? placeholders — NEVER string concatenation
const findByEmail = email => new Promise((res, rej) =>
  db.get('SELECT * FROM users WHERE email = ?', [email], (e, r) => e ? rej(e) : res(r)));

const findById = id => new Promise((res, rej) =>
  db.get('SELECT id,email,role,created FROM users WHERE id = ?', [id], (e, r) => e ? rej(e) : res(r)));

const createUser = (email, password, role = 'user') => new Promise((res, rej) =>
  db.run('INSERT INTO users (email, password, role) VALUES (?, ?, ?)', [email, password, role],
    function(e) { e ? rej(e) : res({ id: this.lastID }); }));

const logAction = (userId, action, ip) => new Promise((res, rej) =>
  db.run('INSERT INTO audit_log (user_id, action, ip) VALUES (?, ?, ?)', [userId, action, ip],
    function(e) { e ? rej(e) : res(); }));

const getAuditLog = () => new Promise((res, rej) =>
  db.all(`SELECT a.*, u.email FROM audit_log a LEFT JOIN users u ON a.user_id=u.id
          ORDER BY a.timestamp DESC LIMIT 30`, [], (e, r) => e ? rej(e) : res(r)));

module.exports = { findByEmail, findById, createUser, logAction, getAuditLog };
