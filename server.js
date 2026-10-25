require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const DATA_DIR = path.resolve(process.env.DATA_DIR || path.join(__dirname, 'data'));
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || '';
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH || '';
const SESSION_SECRET = process.env.SESSION_SECRET || '';
const IS_PROD = process.env.NODE_ENV === 'production';
const MAX_UPLOAD_BYTES = 100 * 1024 * 1024; // 100 MB per request; actual capacity depends on server RAM/disk
const MAX_RECORDS = 1000000;
const SESSION_TTL_MS = 8 * 60 * 60 * 1000;
const FALLBACK_LABELS = ['@CoderArjun', '@Tg_ownner', '@ZAD_OSINT_EXPLOIT_OWNER'];

if (!ADMIN_USERNAME || !ADMIN_PASSWORD_HASH || !SESSION_SECRET || SESSION_SECRET.length < 32) {
  console.error('Missing required env: set ADMIN_USERNAME, ADMIN_PASSWORD_HASH (bcrypt), and SESSION_SECRET (32+ chars).');
  process.exit(1);
}
fs.mkdirSync(DATA_DIR, { recursive: true, mode: 0o700 });
const DB_FILE = path.join(DATA_DIR, 'store.json');
const INDEX_FILE = path.join(DATA_DIR, 'records.json');

function readJson(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch (e) {
    if (e.code === 'ENOENT') return fallback;
    console.error(`Could not read ${path.basename(file)}; using safe default.`, e.message);
    return fallback;
  }
}
function atomicWrite(file, value) {
  const temp = `${file}.${process.pid}.${crypto.randomBytes(4).toString('hex')}.tmp`;
  fs.writeFileSync(temp, JSON.stringify(value, null, 2), { mode: 0o600 });
  fs.renameSync(temp, file);
}
let store = readJson(DB_FILE, { keys: [], audit: [], settings: { fallbackLabels: FALLBACK_LABELS } });
let records = readJson(INDEX_FILE, []);
let sources = readJson(path.join(DATA_DIR, 'sources.json'), []);
if (!Array.isArray(store.keys)) store.keys = [];
if (!Array.isArray(store.audit)) store.audit = [];
if (!Array.isArray(records)) records = [];
if (!Array.isArray(sources)) sources = [];
function saveStore() { atomicWrite(DB_FILE, store); }
function saveRecords() { atomicWrite(INDEX_FILE, records); atomicWrite(path.join(DATA_DIR, 'sources.json'), sources); }
function audit(action, detail = {}) {
  store.audit.unshift({ id: crypto.randomUUID(), at: new Date().toISOString(), action, ...detail });
  store.audit = store.audit.slice(0, 500);
  saveStore();
}
function hashToken(token) { return crypto.createHash('sha256').update(token).digest('hex'); }
function safeEqual(a, b) {
  const aa = Buffer.from(String(a)); const bb = Buffer.from(String(b));
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}
const sessions = new Map();
function signSession(id, expires) {
  const payload = `${id}.${expires}`;
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('hex');
  return `${payload}.${sig}`;
}
function parseSession(cookie) {
  if (!cookie) return null;
  const parts = cookie.split('.');
  if (parts.length !== 3) return null;
  const [id, exp, sig] = parts;
  const expected = crypto.createHmac('sha256', SESSION_SECRET).update(`${id}.${exp}`).digest('hex');
  if (!safeEqual(sig, expected) || Number(exp) < Date.now()) return null;
  const entry = sessions.get(id);
  if (!entry || entry.expires !== Number(exp) || entry.expires < Date.now()) return null;
  return { id, entry };
}
function cookieValue(req, name) {
  const raw = req.headers.cookie || '';
  for (const part of raw.split(';')) {
    const i = part.indexOf('=');
    if (i >= 0 && part.slice(0, i).trim() === name) return decodeURIComponent(part.slice(i + 1).trim());
  }
  return '';
}
function requireAdmin(req, res, next) {
  const session = parseSession(cookieValue(req, 'wg_session'));
  if (!session) return res.status(401).json({ error: 'Authentication required' });
  req.session = session;
  next();
}
function requireCsrf(req, res, next) {
  const token = req.headers['x-csrf-token'];
  if (!token || !safeEqual(token, req.session.entry.csrf)) return res.status(403).json({ error: 'Invalid CSRF token' });
  next();
}
function cleanString(v, max = 200) { return typeof v === 'string' ? v.trim().slice(0, max) : ''; }
function validateRecords(parsed) {
  const arr = Array.isArray(parsed) ? parsed : (parsed && Array.isArray(parsed.records) ? parsed.records : null);
  if (!arr) throw new Error('JSON must be an array of objects or an object containing a records array.');
  if (arr.length > MAX_RECORDS) throw new Error(`Maximum ${MAX_RECORDS} records per import.`);
  const out = [];
  for (const row of arr) {
    if (!row || typeof row !== 'object' || Array.isArray(row)) throw new Error('Every record must be a JSON object.');
    const normalized = {};
    for (const [k, v] of Object.entries(row)) {
      if (!/^[A-Za-z0-9_-]{1,80}$/.test(k)) continue;
      if (['string', 'number', 'boolean'].includes(typeof v) || v === null) normalized[k] = v;
      else throw new Error(`Nested values are not supported (${k}). Flatten the record first.`);
    }
    out.push(normalized);
  }
  return out;
}
function isExpired(key) { return !key.expiresAt || Date.parse(key.expiresAt) <= Date.now(); }
function publicKey(k) {
  return { id: k.id, name: k.name, prefix: k.prefix, createdAt: k.createdAt, expiresAt: k.expiresAt,
    limit: k.limit, used: k.used, status: k.revoked ? 'revoked' : (isExpired(k) ? 'expired' : (k.used >= k.limit ? 'limit_reached' : 'active')) };
}
function recordCount() { return records.length; }
function analyzeRecords(rows) {
  const fields = [...new Set(rows.flatMap(r => Object.keys(r)))].sort();
  return { count: rows.length, fields, sampleCount: Math.min(rows.length, 3) };
}

// Optional hosting-side auto-scan: place authorized JSON files in DATA_DIR/imports/.
// The scan runs only when no indexed dataset exists, so dashboard imports are not overwritten.
function autoScanImportDirectory() {
  if (records.length || sources.length) return;
  const importDir = path.join(DATA_DIR, 'imports');
  if (!fs.existsSync(importDir)) return;
  const names = fs.readdirSync(importDir).filter(n => n.toLowerCase().endsWith('.json')).sort();
  if (!names.length) return;
  try {
    let combined = [];
    const foundSources = [];
    for (const name of names) {
      const full = path.join(importDir, name);
      const stat = fs.statSync(full);
      if (!stat.isFile() || stat.size > MAX_UPLOAD_BYTES) continue;
      const parsed = JSON.parse(fs.readFileSync(full, 'utf8'));
      const rows = validateRecords(parsed);
      combined.push(...rows);
      foundSources.push({ name, count: rows.length, fields: analyzeRecords(rows).fields, importedAt: new Date().toISOString() });
    }
    if (combined.length > MAX_RECORDS) throw new Error(`Combined import exceeds ${MAX_RECORDS} records.`);
    records = combined; sources = foundSources; saveRecords();
    console.log(`Auto-indexed ${sources.length} JSON files (${records.length} records) from ${importDir}`);
  } catch (e) {
    console.error('JSON auto-scan failed:', e.message);
  }
}
autoScanImportDirectory();

app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"], scriptSrc: ["'self'"], styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc: ["'self'", 'https://fonts.gstatic.com'], imgSrc: ["'self'", 'data:'], connectSrc: ["'self'"],
      objectSrc: ["'none'"], frameAncestors: ["'none'"], baseUri: ["'self'"], formAction: ["'self'"]
    }
  },
  crossOriginEmbedderPolicy: false
}));
app.use(express.json({ limit: MAX_UPLOAD_BYTES, strict: true }));
app.use('/api/', rateLimit({ windowMs: 60_000, limit: 120, standardHeaders: 'draft-7', legacyHeaders: false }));
app.use('/auth/', rateLimit({ windowMs: 15 * 60_000, limit: 10, standardHeaders: 'draft-7', legacyHeaders: false }));
app.use(express.static(path.join(__dirname, 'public'), { etag: true, maxAge: IS_PROD ? '1h' : 0 }));

app.get('/health', (req, res) => res.json({ ok: true }));
app.get('/api/auth/me', (req, res) => {
  const s = parseSession(cookieValue(req, 'wg_session'));
  if (!s) return res.json({ authenticated: false });
  res.json({ authenticated: true, username: s.entry.username, csrfToken: s.entry.csrf });
});
app.post('/auth/login', async (req, res) => {
  const username = cleanString(req.body?.username, 100);
  const password = typeof req.body?.password === 'string' ? req.body.password : '';
  let ok = false;
  try { ok = safeEqual(username, ADMIN_USERNAME) && await bcrypt.compare(password, ADMIN_PASSWORD_HASH); } catch (_) {}
  if (!ok) {
    audit('login_failed');
    return res.status(401).json({ error: 'Invalid username or password' });
  }
  const id = crypto.randomBytes(24).toString('hex');
  const expires = Date.now() + SESSION_TTL_MS;
  const csrf = crypto.randomBytes(24).toString('hex');
  sessions.set(id, { username, expires, csrf });
  res.setHeader('Set-Cookie', `wg_session=${encodeURIComponent(signSession(id, expires))}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${Math.floor(SESSION_TTL_MS/1000)}${IS_PROD ? '; Secure' : ''}`);
  audit('login_success', { username });
  res.json({ ok: true, csrfToken: csrf });
});
app.post('/auth/logout', requireAdmin, requireCsrf, (req, res) => {
  sessions.delete(req.session.id);
  res.setHeader('Set-Cookie', `wg_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0${IS_PROD ? '; Secure' : ''}`);
  res.json({ ok: true });
});
app.get('/api/dashboard', requireAdmin, (req, res) => {
  const keys = store.keys.map(publicKey);
  res.json({ records: recordCount(), fields: [...new Set(records.flatMap(r => Object.keys(r)))].slice(0, 100), sources: sources.map(x => ({ name: x.name, count: x.count, fields: x.fields, importedAt: x.importedAt })),
    totalKeys: keys.length, activeKeys: keys.filter(k => k.status === 'active').length,
    requests: store.keys.reduce((n, k) => n + (k.used || 0), 0), keys,
    fallbackLabels: store.settings?.fallbackLabels || FALLBACK_LABELS, lookupField: process.env.LOOKUP_FIELD || 'MOBILE', responseFields: (process.env.RESPONSE_FIELDS || 'MOBILE').split(',').map(s => s.trim()).filter(Boolean) });
});
app.get('/api/records/preview', requireAdmin, (req, res) => {
  const limit = Math.min(20, Math.max(1, Number(req.query.limit) || 10));
  res.json({ records: records.slice(0, limit).map(r => {
    const out = { ...r };
    for (const k of Object.keys(out)) if (/email|phone|mobile|address/i.test(k)) out[k] = out[k] ? '[REDACTED IN PREVIEW]' : out[k];
    return out;
  }) });
});
app.post('/api/records/import', requireAdmin, requireCsrf, (req, res) => {
  try {
    // Multi-file mode: { files: [{ name, records: [...] }, ...] } replaces all indexed sources.
    // Single-file mode remains supported and also replaces the current indexed dataset.
    const incomingFiles = Array.isArray(req.body?.files) ? req.body.files : null;
    let nextRecords = [];
    let nextSources = [];
    if (incomingFiles) {
      if (!incomingFiles.length) throw new Error('Provide at least one JSON file.');
      for (const item of incomingFiles) {
        const name = cleanString(item?.name, 120) || `source-${nextSources.length + 1}.json`;
        const rows = validateRecords(item?.records);
        const analysis = analyzeRecords(rows);
        nextSources.push({ name, count: rows.length, fields: analysis.fields, importedAt: new Date().toISOString() });
        nextRecords.push(...rows);
      }
    } else {
      const rows = validateRecords(req.body?.records ?? req.body);
      nextSources = [{ name: cleanString(req.body?.sourceName, 120) || 'import.json', count: rows.length, fields: analyzeRecords(rows).fields, importedAt: new Date().toISOString() }];
      nextRecords = rows;
    }
    if (nextRecords.length > MAX_RECORDS) throw new Error(`Maximum ${MAX_RECORDS} combined records across all files.`);
    records = nextRecords;
    sources = nextSources;
    saveRecords();
    audit('records_imported', { count: records.length, files: sources.length });
    res.json({ ok: true, count: records.length, files: sources.length, sources, fields: [...new Set(records.flatMap(r => Object.keys(r)))].slice(0, 100) });
  } catch (e) { res.status(400).json({ error: e.message }); }
});
app.post('/api/keys', requireAdmin, requireCsrf, (req, res) => {
  const name = cleanString(req.body?.name, 80);
  const days = Number(req.body?.days);
  const limit = Number(req.body?.limit);
  if (!name) return res.status(400).json({ error: 'Key name is required' });
  if (!Number.isInteger(days) || days < 1 || days > 3650) return res.status(400).json({ error: 'Expiry must be 1–3650 days' });
  if (!Number.isInteger(limit) || limit < 1 || limit > 10_000_000) return res.status(400).json({ error: 'Limit must be 1–10,000,000 requests' });
  const token = `wg_${crypto.randomBytes(32).toString('base64url')}`;
  const now = new Date();
  const key = { id: crypto.randomUUID(), name, prefix: token.slice(0, 10), tokenHash: hashToken(token),
    createdAt: now.toISOString(), expiresAt: new Date(now.getTime() + days * 86400000).toISOString(),
    limit, used: 0, revoked: false };
  store.keys.unshift(key); saveStore(); audit('key_created', { id: key.id, name });
  res.status(201).json({ key: publicKey(key), token });
});
app.post('/api/keys/:id/revoke', requireAdmin, requireCsrf, (req, res) => {
  const key = store.keys.find(k => k.id === req.params.id);
  if (!key) return res.status(404).json({ error: 'Key not found' });
  key.revoked = true; saveStore(); audit('key_revoked', { id: key.id }); res.json({ ok: true, key: publicKey(key) });
});
app.delete('/api/keys/:id', requireAdmin, requireCsrf, (req, res) => {
  const before = store.keys.length;
  store.keys = store.keys.filter(k => k.id !== req.params.id);
  if (store.keys.length === before) return res.status(404).json({ error: 'Key not found' });
  saveStore(); audit('key_deleted', { id: req.params.id }); res.json({ ok: true });
});
app.get('/api/audit', requireAdmin, (req, res) => res.json({ events: store.audit.slice(0, 100) }));

// Public lookup: only exact match against the explicitly configured lookup field.
// Responses intentionally return only allowlisted fields to avoid exposing whole source records.
app.get('/v1/lookup', (req, res) => {
  const token = String(req.get('x-api-key') || req.query.api_key || '');
  if (!token || token.length > 200) return res.status(401).json({ error: 'API key required' });
  const key = store.keys.find(k => safeEqual(k.tokenHash, hashToken(token)));
  if (!key || key.revoked) return res.status(401).json({ error: 'Invalid or revoked API key' });
  if (isExpired(key)) return res.status(401).json({ error: 'API key expired', expiredAt: key.expiresAt });
  if (key.used >= key.limit) return res.status(429).json({ error: 'API request quota exceeded', limit: key.limit });
  const lookupField = cleanString(process.env.LOOKUP_FIELD || 'MOBILE', 80);
  const query = cleanString(req.query.q, 120);
  if (!query) return res.status(400).json({ error: 'Provide an exact lookup value in ?q=' });
  key.used += 1; saveStore();
  const match = records.find(r => String(r[lookupField] ?? '') === query);
  audit('api_request', { keyId: key.id, found: Boolean(match) });
  const labels = store.settings?.fallbackLabels || FALLBACK_LABELS;
  if (!match) return res.status(404).json({ found: false, query, message: 'Record not found in the configured database', labels });
  const allowed = (process.env.RESPONSE_FIELDS || 'MOBILE').split(',').map(s => s.trim()).filter(Boolean);
  const data = {};
  for (const field of allowed) if (Object.prototype.hasOwnProperty.call(match, field)) data[field] = match[field];
  res.json({ found: true, data, labels });
});

app.use((err, req, res, next) => {
  console.error(err.message);
  if (res.headersSent) return next(err);
  res.status(err.status || 500).json({ error: err.status === 413 ? 'Request too large (100 MB max)' : 'Request could not be processed' });
});
app.listen(PORT, '0.0.0.0', () => console.log(`White Glass API Maker listening on ${PORT}`));
