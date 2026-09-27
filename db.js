const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');

const dbPath = process.env.DB_PATH || path.join(__dirname, 'data', 'nemurumah.db');
fs.mkdirSync(path.dirname(dbPath), { recursive: true });
const db = new Database(dbPath);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL,
 email TEXT NOT NULL UNIQUE,
 password_hash TEXT NOT NULL,
 role TEXT NOT NULL DEFAULT 'admin',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS properties (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 title TEXT NOT NULL,
 type TEXT NOT NULL,
 purpose TEXT NOT NULL,
 price INTEGER NOT NULL DEFAULT 0,
 price_label TEXT,
 location TEXT NOT NULL,
 address TEXT,
 description TEXT,
 bedrooms INTEGER DEFAULT 0,
 bathrooms INTEGER DEFAULT 0,
 land_area INTEGER DEFAULT 0,
 building_area INTEGER DEFAULT 0,
 latitude REAL,
 longitude REAL,
 whatsapp TEXT,
 status TEXT NOT NULL DEFAULT 'published',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS property_images (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 property_id INTEGER NOT NULL,
 filename TEXT NOT NULL,
 original_name TEXT,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(property_id) REFERENCES properties(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS ad_requests (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 owner_name TEXT NOT NULL,
 phone TEXT NOT NULL,
 email TEXT,
 property_title TEXT NOT NULL,
 property_type TEXT NOT NULL,
 purpose TEXT NOT NULL,
 location TEXT NOT NULL,
 price INTEGER DEFAULT 0,
 description TEXT,
 status TEXT NOT NULL DEFAULT 'new',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS sessions (
 sid TEXT PRIMARY KEY,
 sess TEXT NOT NULL,
 expire INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_properties_status ON properties(status);
CREATE INDEX IF NOT EXISTS idx_properties_location ON properties(location);
CREATE INDEX IF NOT EXISTS idx_ad_requests_status ON ad_requests(status);
CREATE INDEX IF NOT EXISTS idx_sessions_expire ON sessions(expire);
`);

const email = String(process.env.ADMIN_EMAIL || '').trim().toLowerCase();
const password = String(process.env.ADMIN_PASSWORD || '');
if (!email || !password || password.length < 12) {
  console.warn('ADMIN_EMAIL/ADMIN_PASSWORD belum diset dengan benar. Set keduanya sebelum login produksi.');
} else {
  const existing = db.prepare('SELECT id FROM users WHERE email=?').get(email);
  if (!existing) {
    const hash = bcrypt.hashSync(password, 12);
    db.prepare('INSERT INTO users(name,email,password_hash,role) VALUES (?,?,?,?)')
      .run('Administrator NemuRumah', email, hash, 'admin');
    console.log(`Admin awal dibuat: ${email}`);
  }
}

module.exports = db;
