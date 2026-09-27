require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const db = require('./db');
const SQLiteSessionStore = require('./session-store');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const isProd = process.env.NODE_ENV === 'production';
if (isProd && (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32)) {
  throw new Error('SESSION_SECRET minimal 32 karakter wajib di production.');
}
app.disable('x-powered-by');
if (isProd) app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(compression());
app.use(express.urlencoded({ extended: true, limit: '1mb' }));
app.use(express.json({ limit: '1mb' }));

const uploadDir = path.join(__dirname, 'public', 'uploads');
fs.mkdirSync(uploadDir, { recursive: true });
const maxUploadMB = Number(process.env.MAX_UPLOAD_MB || 5);
const storage = multer.diskStorage({
  destination: uploadDir,
  filename: (req, file, cb) => cb(null, `${Date.now()}-${crypto.randomBytes(10).toString('hex')}${path.extname(file.originalname).toLowerCase()}`)
});
const upload = multer({
  storage,
  limits: { fileSize: maxUploadMB * 1024 * 1024, files: 12 },
  fileFilter: (req, file, cb) => {
    if (/^image\/(jpeg|png|webp)$/.test(file.mimetype)) return cb(null, true);
    cb(new Error('Foto harus JPG, PNG, atau WEBP.'));
  }
});

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

const store = new SQLiteSessionStore(db);
app.use(session({
  store,
  secret: process.env.SESSION_SECRET || 'development-only-change-this-secret',
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: isProd,
    maxAge: 8 * 60 * 60 * 1000
  }
}));
setInterval(() => store.cleanup(), 30 * 60 * 1000).unref();

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Terlalu banyak percobaan login. Coba lagi beberapa menit lagi.'
});
app.use('/login', loginLimiter);

app.use((req, res, next) => {
  if (!req.session.csrf) req.session.csrf = crypto.randomBytes(32).toString('hex');
  res.locals.user = req.session.user || null;
  res.locals.csrf = req.session.csrf;
  res.locals.wa = process.env.WHATSAPP_NUMBER || '';
  res.locals.baseUrl = process.env.BASE_URL || '';
  res.locals.mapsKey = process.env.GOOGLE_MAPS_API_KEY || '';
  next();
});

function verifyCsrf(req, res, next) {
  const token = req.body && req.body._csrf;
  if (!token || !req.session.csrf || Buffer.byteLength(token) !== Buffer.byteLength(req.session.csrf) || !crypto.timingSafeEqual(Buffer.from(token), Buffer.from(req.session.csrf))) {
    return res.status(403).send('Permintaan tidak valid (CSRF). Silakan refresh halaman dan coba lagi.');
  }
  next();
}
function requireAuth(req, res, next) {
  if (req.session.user) return next();
  res.redirect('/login?next=' + encodeURIComponent(req.originalUrl));
}
function cleanNext(next) { return typeof next === 'string' && next.startsWith('/') && !next.startsWith('//') ? next : '/admin'; }
function normalizeWa(v) { return String(v || '').replace(/[^0-9]/g, ''); }
function safeUnlink(filename) { try { fs.unlinkSync(path.join(uploadDir, filename)); } catch {} }
function getProperty(id) {
  const p = db.prepare('SELECT * FROM properties WHERE id=?').get(id);
  if (!p) return null;
  p.images = db.prepare('SELECT * FROM property_images WHERE property_id=? ORDER BY id').all(id);
  return p;
}

app.get('/', (req, res) => {
  const { q, type, purpose } = req.query;
  let sql = `SELECT * FROM properties WHERE status='published'`;
  const params = [];
  if (q) { sql += ' AND (title LIKE ? OR location LIKE ? OR description LIKE ?)'; const x = `%${q}%`; params.push(x, x, x); }
  if (type) { sql += ' AND type=?'; params.push(type); }
  if (purpose) { sql += ' AND purpose=?'; params.push(purpose); }
  sql += ' ORDER BY id DESC';
  const props = db.prepare(sql).all(...params);
  props.forEach(p => p.images = db.prepare('SELECT * FROM property_images WHERE property_id=? ORDER BY id LIMIT 1').all(p.id));
  res.render('home', { props, q: q || '', type: type || '', purpose: purpose || '' });
});

app.get('/properti/:id', (req, res) => {
  const p = getProperty(req.params.id);
  if (!p || p.status !== 'published') return res.status(404).render('404');
  res.render('detail', { p });
});

app.get('/pasang-iklan', (req, res) => res.render('ad-form', { success: req.query.success }));
app.post('/pasang-iklan', verifyCsrf, upload.none(), (req, res) => {
  const { owner_name, phone, email, property_title, property_type, purpose, location, price, description } = req.body;
  if (!owner_name || !phone || !property_title || !property_type || !purpose || !location) return res.status(400).send('Data wajib belum lengkap.');
  db.prepare(`INSERT INTO ad_requests(owner_name,phone,email,property_title,property_type,purpose,location,price,description) VALUES (?,?,?,?,?,?,?,?,?)`)
    .run(owner_name.trim(), phone.trim(), (email || '').trim(), property_title.trim(), property_type, purpose, location.trim(), Number(price || 0), (description || '').trim());
  res.redirect('/pasang-iklan?success=1');
});

app.get('/login', (req, res) => res.render('login', { error: null, next: cleanNext(req.query.next || '/admin') }));
app.post('/login', verifyCsrf, (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const next = cleanNext(req.body.next || '/admin');
  const u = db.prepare('SELECT * FROM users WHERE email=?').get(email);
  if (!u || !bcrypt.compareSync(password, u.password_hash)) return res.status(401).render('login', { error: 'Email atau password salah.', next });
  req.session.regenerate(err => {
    if (err) return res.status(500).send('Gagal membuat sesi login.');
    req.session.csrf = crypto.randomBytes(32).toString('hex');
    req.session.user = { id: u.id, name: u.name, email: u.email, role: u.role };
    res.redirect(next);
  });
});
app.post('/logout', requireAuth, verifyCsrf, (req, res) => req.session.destroy(() => res.redirect('/')));

app.get('/admin', requireAuth, (req, res) => {
  const props = db.prepare('SELECT * FROM properties ORDER BY id DESC').all();
  const requests = db.prepare('SELECT * FROM ad_requests ORDER BY id DESC').all();
  const stats = {
    properties: db.prepare("SELECT COUNT(*) c FROM properties WHERE status='published'").get().c,
    requests: db.prepare("SELECT COUNT(*) c FROM ad_requests WHERE status='new'").get().c,
    photos: db.prepare('SELECT COUNT(*) c FROM property_images').get().c
  };
  res.render('admin', { props, requests, stats });
});

app.get('/admin/properti/new', requireAuth, (req, res) => res.render('property-form', { p: null, action: '/admin/properti/new' }));
app.post('/admin/properti/new', requireAuth, verifyCsrf, upload.array('images', 12), (req, res) => {
  const p = saveProperty(req.body);
  saveImages(p.lastInsertRowid, req.files);
  res.redirect('/admin');
});
app.get('/admin/properti/:id/edit', requireAuth, (req, res) => {
  const p = getProperty(req.params.id);
  if (!p) return res.status(404).render('404');
  res.render('property-form', { p, action: `/admin/properti/${p.id}/edit` });
});
app.post('/admin/properti/:id/edit', requireAuth, verifyCsrf, upload.array('images', 12), (req, res) => {
  updateProperty(req.params.id, req.body);
  saveImages(req.params.id, req.files);
  res.redirect('/admin');
});
app.post('/admin/properti/:id/delete', requireAuth, verifyCsrf, (req, res) => {
  const p = getProperty(req.params.id);
  if (p) { p.images.forEach(i => safeUnlink(i.filename)); db.prepare('DELETE FROM properties WHERE id=?').run(req.params.id); }
  res.redirect('/admin');
});
app.post('/admin/properti/:id/image/:imageId/delete', requireAuth, verifyCsrf, (req, res) => {
  const img = db.prepare('SELECT * FROM property_images WHERE id=? AND property_id=?').get(req.params.imageId, req.params.id);
  if (img) { safeUnlink(img.filename); db.prepare('DELETE FROM property_images WHERE id=?').run(img.id); }
  res.redirect('/admin/properti/' + req.params.id + '/edit');
});
app.post('/admin/request/:id/status', requireAuth, verifyCsrf, (req, res) => {
  const allowed = new Set(['new', 'contacted', 'approved', 'rejected']);
  if (!allowed.has(req.body.status)) return res.status(400).send('Status tidak valid.');
  db.prepare('UPDATE ad_requests SET status=? WHERE id=?').run(req.body.status, req.params.id);
  res.redirect('/admin');
});

app.get('/admin/account', requireAuth, (req, res) => res.render('account', { error: null, success: null }));
app.post('/admin/account', requireAuth, verifyCsrf, (req, res) => {
  const current = String(req.body.current_password || '');
  const next = String(req.body.new_password || '');
  const confirm = String(req.body.confirm_password || '');
  const u = db.prepare('SELECT * FROM users WHERE id=?').get(req.session.user.id);
  if (!u || !bcrypt.compareSync(current, u.password_hash)) return res.status(400).render('account', { error: 'Password saat ini salah.', success: null });
  if (next.length < 12) return res.status(400).render('account', { error: 'Password baru minimal 12 karakter.', success: null });
  if (next !== confirm) return res.status(400).render('account', { error: 'Konfirmasi password tidak sama.', success: null });
  db.prepare('UPDATE users SET password_hash=?, updated_at=CURRENT_TIMESTAMP WHERE id=?').run(bcrypt.hashSync(next, 12), u.id);
  res.render('account', { error: null, success: 'Password berhasil diubah. Gunakan password baru saat login berikutnya.' });
});

function saveProperty(b) {
  const wa = normalizeWa(b.whatsapp) || normalizeWa(process.env.WHATSAPP_NUMBER);
  return db.prepare(`INSERT INTO properties(title,type,purpose,price,price_label,location,address,description,bedrooms,bathrooms,land_area,building_area,latitude,longitude,whatsapp,status) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run(String(b.title || '').trim(), b.type, b.purpose, Number(b.price || 0), String(b.price_label || '').trim(), String(b.location || '').trim(), String(b.address || '').trim(), String(b.description || '').trim(), Number(b.bedrooms || 0), Number(b.bathrooms || 0), Number(b.land_area || 0), Number(b.building_area || 0), b.latitude ? Number(b.latitude) : null, b.longitude ? Number(b.longitude) : null, wa, b.status === 'draft' ? 'draft' : 'published');
}
function updateProperty(id, b) {
  const wa = normalizeWa(b.whatsapp) || normalizeWa(process.env.WHATSAPP_NUMBER);
  db.prepare(`UPDATE properties SET title=?,type=?,purpose=?,price=?,price_label=?,location=?,address=?,description=?,bedrooms=?,bathrooms=?,land_area=?,building_area=?,latitude=?,longitude=?,whatsapp=?,status=?,updated_at=CURRENT_TIMESTAMP WHERE id=?`)
    .run(String(b.title || '').trim(), b.type, b.purpose, Number(b.price || 0), String(b.price_label || '').trim(), String(b.location || '').trim(), String(b.address || '').trim(), String(b.description || '').trim(), Number(b.bedrooms || 0), Number(b.bathrooms || 0), Number(b.land_area || 0), Number(b.building_area || 0), b.latitude ? Number(b.latitude) : null, b.longitude ? Number(b.longitude) : null, wa, b.status === 'draft' ? 'draft' : 'published', id);
}
function saveImages(id, files) {
  const stmt = db.prepare('INSERT INTO property_images(property_id,filename,original_name) VALUES (?,?,?)');
  for (const f of (files || [])) stmt.run(id, f.filename, f.originalname);
}

app.use((err, req, res, next) => {
  console.error(err);
  if (err instanceof multer.MulterError) return res.status(400).send(`Upload gagal: ${err.message}`);
  res.status(400).send(err.message || 'Terjadi kesalahan.');
});
app.use((req, res) => res.status(404).render('404'));

app.listen(PORT, () => console.log(`NemuRumah running on port ${PORT}`));
