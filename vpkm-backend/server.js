const express = require('express');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3001;

const SECRET = process.env.JWT_SECRET;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

if (!SECRET) { console.error('❌ Brak JWT_SECRET'); process.exit(1); }
if (!ADMIN_PASSWORD) { console.error('❌ Brak ADMIN_PASSWORD'); process.exit(1); }

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }));
app.set('trust proxy', 1);

const allowedOrigins = (process.env.FRONTEND_URL || 'http://localhost:5173')
  .split(',').map(s => s.trim()).filter(Boolean);

app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) { callback(null, true); }
    else { console.warn(`⚠️ Zablokowane CORS z: ${origin}`); callback(new Error('Niedozwolone pochodzenie (CORS)')); }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

const globalLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 1000, standardHeaders: true, legacyHeaders: false, message: { error: 'Za dużo zapytań.' } });
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100, standardHeaders: true, legacyHeaders: false, message: { error: 'Za dużo prób logowania. Poczekaj 15 minut.' } });

app.use(globalLimiter);
app.use(express.json());

const dir = './uploads';
if (!fs.existsSync(dir)) fs.mkdirSync(dir);
const plateDir = './uploads/plates';
if (!fs.existsSync(plateDir)) fs.mkdirSync(plateDir, { recursive: true });

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const safeName = file.originalname.replace(/[^a-zA-Z0-9.\-_]/g, '_');
    cb(null, uniqueSuffix + '-' + safeName);
  }
});
const pdfFileFilter = (req, file, cb) => {
  if (file.mimetype === 'application/pdf' && path.extname(file.originalname).toLowerCase() === '.pdf') cb(null, true);
  else cb(new Error('Tylko pliki PDF są dozwolone.'));
};
const upload = multer({ storage, limits: { fileSize: 10 * 1024 * 1024 }, fileFilter: pdfFileFilter });

const plateStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/plates/'),
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const safeName = file.originalname.replace(/[^a-zA-Z0-9.\-_]/g, '_');
    cb(null, uniqueSuffix + '-' + safeName);
  }
});
const imageFileFilter = (req, file, cb) => {
  const allowedMimes = ['image/jpeg', 'image/png', 'image/jpg'];
  const allowedExts = ['.jpg', '.jpeg', '.png'];
  if (allowedMimes.includes(file.mimetype) && allowedExts.includes(path.extname(file.originalname).toLowerCase())) cb(null, true);
  else cb(new Error('Tylko pliki JPG/PNG są dozwolone.'));
};
const uploadPlateImage = multer({ storage: plateStorage, limits: { fileSize: 5 * 1024 * 1024 }, fileFilter: imageFileFilter });

const requireAuth = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ error: 'Brak tokenu autoryzacji' });
  const token = authHeader.split(' ')[1];
  try { req.user = jwt.verify(token, SECRET); next(); }
  catch { return res.status(401).json({ error: 'Token nieprawidłowy lub wygasł' }); }
};

const requireAdmin = (req, res, next) => {
  requireAuth(req, res, () => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Brak uprawnień administratora' });
    next();
  });
};

// ---------------------------------------------------------
// 🗄️ INICJALIZACJA BAZY
// ---------------------------------------------------------
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      login TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'driver',
      "displayName" TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS fleet (
      id TEXT PRIMARY KEY,
      "busNumber" TEXT,
      brand TEXT,
      model TEXT,
      "vehicleType" TEXT,
      status TEXT DEFAULT 'eksploatowany',
      "yearManufactured" TEXT,
      "assignedDriverId" TEXT DEFAULT '',
      "assignedDriverName" TEXT DEFAULT 'Brak',
      notes TEXT DEFAULT '',
      "plateImageUrl" TEXT DEFAULT ''
    );

    CREATE TABLE IF NOT EXISTS shifts (
      id BIGINT PRIMARY KEY,
      "driverId" TEXT,
      "driverName" TEXT,
      line TEXT,
      brigade TEXT,
      bus TEXT,
      "startTime" TEXT,
      "endTime" TEXT,
      "pdfUrl" TEXT,
      status TEXT DEFAULT 'active',
      "createdAt" TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS reports (
      id BIGINT PRIMARY KEY,
      "driverId" TEXT,
      "driverName" TEXT,
      line TEXT,
      date TEXT,
      "pdfUrl" TEXT,
      "originalName" TEXT,
      status TEXT DEFAULT 'pending'
    );

    CREATE TABLE IF NOT EXISTS messages (
      id BIGINT PRIMARY KEY,
      "fromId" TEXT,
      "fromName" TEXT,
      "toId" TEXT,
      "toName" TEXT,
      content TEXT,
      "createdAt" TIMESTAMPTZ DEFAULT NOW(),
      "is_global" BOOLEAN DEFAULT FALSE
    );

    CREATE TABLE IF NOT EXISTS message_reads (
      "messageId" BIGINT,
      "userId" TEXT,
      PRIMARY KEY ("messageId", "userId")
    );
  `);
  console.log('✅ Tabele zainicjalizowane');
}

// ---------------------------------------------------------
// 🚀 ENDPOINTY PUBLICZNE
// ---------------------------------------------------------
app.get('/', (req, res) => res.send('Serwer vPKM działa poprawnie!'));

app.post('/api/login', loginLimiter, async (req, res) => {
  const { login, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE login = $1', [login]);
    const user = result.rows[0];
    if (!user) return res.status(401).json({ success: false, message: 'Błędny login lub hasło!' });
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) return res.status(401).json({ success: false, message: 'Błędny login lub hasło!' });
    const token = jwt.sign({ id: user.id, role: user.role, displayName: user.displayName || user.displayname }, SECRET, { expiresIn: '8h' });
    res.json({
      success: true,
      user: { id: user.id, login: user.login, role: user.role, displayName: user.displayName || user.displayname },
      token
    });
  } catch (err) { console.error(err); res.status(500).json({ success: false, message: 'Błąd serwera' }); }
});

// ---------------------------------------------------------
// 🚀 KIEROWCA I ADMIN
// ---------------------------------------------------------
app.get('/api/drivers', requireAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, login, "displayName" FROM users WHERE role = $1', ['driver']);
    res.json(result.rows.map(d => ({ id: d.id, login: d.login, displayName: d.displayName || d.displayname })));
  } catch (err) { console.error(err); res.status(500).json({ error: 'Błąd serwera' }); }
});

app.get('/api/shifts/:driverId', requireAuth, async (req, res) => {
  if (req.user.role === 'driver' && req.user.id !== req.params.driverId) return res.status(403).json({ error: 'Możesz sprawdzać tylko swoją służbę' });
  try {
    const result = await pool.query('SELECT * FROM shifts WHERE "driverId" = $1 AND status = $2', [req.params.driverId, 'active']);
    res.json({ shift: result.rows[0] || null });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Błąd serwera' }); }
});

app.get('/api/shifts/history/:driverId', requireAuth, async (req, res) => {
  if (req.user.role === 'driver' && req.user.id !== req.params.driverId) return res.status(403).json({ error: 'Brak dostępu' });
  try {
    const result = await pool.query('SELECT * FROM shifts WHERE "driverId" = $1 AND status != $2 ORDER BY "createdAt" DESC LIMIT 20', [req.params.driverId, 'active']);
    res.json({ history: result.rows });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Błąd serwera' }); }
});

app.post('/api/reports', requireAuth, upload.single('report_pdf'), async (req, res) => {
  const file = req.file;
  if (!file) return res.status(400).json({ error: 'Brak pliku PDF!' });
  try {
    const id = Date.now();
    const newReport = {
      id,
      driverId: req.body.driverId,
      driverName: req.body.driverName,
      line: req.body.line,
      date: new Date().toLocaleString('pl-PL'),
      pdfUrl: `/api/files/${file.filename}`,
      originalName: file.originalname,
      status: 'pending'
    };
    await pool.query(
      'INSERT INTO reports (id, "driverId", "driverName", line, date, "pdfUrl", "originalName", status) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)',
      [id, newReport.driverId, newReport.driverName, newReport.line, newReport.date, newReport.pdfUrl, newReport.originalName, 'pending']
    );
    await pool.query('UPDATE shifts SET status = $1 WHERE "driverId" = $2 AND status = $3', ['completed', req.body.driverId, 'active']);
    res.json({ success: true });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Błąd serwera' }); }
});

app.get('/api/fleet', requireAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM fleet ORDER BY "busNumber"');
    res.json(result.rows);
  } catch (err) { console.error(err); res.status(500).json({ error: 'Błąd serwera' }); }
});

app.post('/api/change-password', requireAuth, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!newPassword || newPassword.length < 6) return res.status(400).json({ error: 'Nowe hasło musi mieć minimum 6 znaków' });
  try {
    const result = await pool.query('SELECT * FROM users WHERE id = $1', [req.user.id]);
    const user = result.rows[0];
    if (!user) return res.status(404).json({ error: 'Nie znaleziono użytkownika' });
    const passwordMatch = await bcrypt.compare(currentPassword, user.password);
    if (!passwordMatch) return res.status(401).json({ error: 'Obecne hasło jest nieprawidłowe' });
    const hashed = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE users SET password = $1 WHERE id = $2', [hashed, req.user.id]);
    res.json({ success: true });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Błąd serwera' }); }
});

app.get('/api/files/:filename', requireAuth, async (req, res) => {
  const filename = req.params.filename;
  if (filename.includes('..') || filename.includes('/') || filename.includes('\\')) return res.status(400).json({ error: 'Nieprawidłowa nazwa pliku' });
  const filePath = path.join(__dirname, 'uploads', filename);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'Plik nie istnieje' });
  if (req.user.role === 'admin') return res.sendFile(filePath);
  const relativeUrl = `/api/files/${filename}`;
  try {
    const shiftResult = await pool.query('SELECT id FROM shifts WHERE "pdfUrl" = $1 AND "driverId" = $2', [relativeUrl, req.user.id]);
    const reportResult = await pool.query('SELECT id FROM reports WHERE "pdfUrl" = $1 AND "driverId" = $2', [relativeUrl, req.user.id]);
    if (shiftResult.rows.length > 0 || reportResult.rows.length > 0) return res.sendFile(filePath);
    return res.status(403).json({ error: 'Brak dostępu do tego pliku' });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Błąd serwera' }); }
});

app.get('/api/plate-images/:filename', (req, res) => {
  const filename = req.params.filename;
  if (filename.includes('..') || filename.includes('/') || filename.includes('\\')) return res.status(400).json({ error: 'Nieprawidłowa nazwa pliku' });
  const filePath = path.join(__dirname, 'uploads', 'plates', filename);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'Plik nie istnieje' });
  res.sendFile(filePath);
});

// ---------------------------------------------------------
// 🚀 TYLKO ADMIN
// ---------------------------------------------------------
app.post('/api/fleet', requireAdmin, uploadPlateImage.single('plate_image'), async (req, res) => {
  const { busNumber, brand, model, vehicleType, status, yearManufactured, assignedDriverId, assignedDriverName, notes } = req.body;
  const file = req.file;
  const id = 'bus-' + Date.now();
  const plateImageUrl = file ? `/api/plate-images/${file.filename}` : '';
  try {
    await pool.query(
      `INSERT INTO fleet (id, "busNumber", brand, model, "vehicleType", status, "yearManufactured", "assignedDriverId", "assignedDriverName", notes, "plateImageUrl") VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
      [id, busNumber || '', brand || '', model || '', vehicleType || '', status || 'eksploatowany', yearManufactured || '', assignedDriverId || '', assignedDriverName || 'Brak', notes || '', plateImageUrl]
    );
    const result = await pool.query('SELECT * FROM fleet WHERE id = $1', [id]);
    res.json({ success: true, vehicle: result.rows[0] });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Błąd serwera' }); }
});

app.put('/api/fleet/:id', requireAdmin, uploadPlateImage.single('plate_image'), async (req, res) => {
  const { id } = req.params;
  const { busNumber, brand, model, vehicleType, status, yearManufactured, assignedDriverId, assignedDriverName, notes } = req.body;
  const file = req.file;
  try {
    const existing = await pool.query('SELECT * FROM fleet WHERE id = $1', [id]);
    if (existing.rows.length === 0) return res.status(404).json({ error: 'Nie znaleziono pojazdu' });
    const plateImageUrl = file ? `/api/plate-images/${file.filename}` : existing.rows[0].plateImageUrl;
    await pool.query(
      `UPDATE fleet SET "busNumber"=$1, brand=$2, model=$3, "vehicleType"=$4, status=$5, "yearManufactured"=$6, "assignedDriverId"=$7, "assignedDriverName"=$8, notes=$9, "plateImageUrl"=$10 WHERE id=$11`,
      [busNumber, brand, model, vehicleType, status, yearManufactured, assignedDriverId || '', assignedDriverName || 'Brak', notes, plateImageUrl, id]
    );
    const result = await pool.query('SELECT * FROM fleet WHERE id = $1', [id]);
    res.json({ success: true, vehicle: result.rows[0] });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Błąd serwera' }); }
});

app.delete('/api/fleet/:id', requireAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM fleet WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Błąd serwera' }); }
});

app.post('/api/drivers', requireAdmin, async (req, res) => {
  const { login, password, displayName } = req.body;
  try {
    const existing = await pool.query('SELECT id FROM users WHERE login = $1', [login]);
    if (existing.rows.length > 0) return res.status(400).json({ success: false, message: 'Ten login jest już zajęty!' });
    const hashedPassword = await bcrypt.hash(password, 10);
    const id = 'driver-' + Date.now();
    await pool.query('INSERT INTO users (id, login, password, role, "displayName") VALUES ($1,$2,$3,$4,$5)', [id, login, hashedPassword, 'driver', displayName]);
    res.json({ success: true, driver: { id, login, displayName, role: 'driver' } });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Błąd serwera' }); }
});

app.delete('/api/drivers/:id', requireAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query('SELECT id FROM users WHERE id = $1 AND role = $2', [id, 'driver']);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Nie znaleziono kierowcy' });
    await pool.query('DELETE FROM users WHERE id = $1', [id]);
    await pool.query('UPDATE fleet SET "assignedDriverId" = $1, "assignedDriverName" = $2 WHERE "assignedDriverId" = $3', ['', 'Brak', id]);
    res.json({ success: true });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Błąd serwera' }); }
});

app.post('/api/shifts', requireAdmin, upload.single('pdf_file'), async (req, res) => {
  const data = req.body;
  const file = req.file;
  try {
    await pool.query('UPDATE shifts SET status = $1 WHERE "driverId" = $2 AND status = $3', ['cancelled', data.driverId, 'active']);
    const id = Date.now();
    await pool.query(
      `INSERT INTO shifts (id, "driverId", "driverName", line, brigade, bus, "startTime", "endTime", "pdfUrl", status) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
      [id, data.driverId, data.driverName, data.line, data.brigade, data.bus, data.startTime, data.endTime, file ? `/api/files/${file.filename}` : null, 'active']
    );
    const result = await pool.query('SELECT * FROM shifts WHERE id = $1', [id]);
    res.json({ success: true, shift: result.rows[0] });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Błąd serwera' }); }
});

app.get('/api/shifts', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM shifts WHERE status = $1 ORDER BY "createdAt" DESC', ['active']);
    res.json({ shifts: result.rows });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Błąd serwera' }); }
});

app.delete('/api/shifts/:driverId', requireAdmin, async (req, res) => {
  try {
    await pool.query('UPDATE shifts SET status = $1 WHERE "driverId" = $2 AND status = $3', ['cancelled', req.params.driverId, 'active']);
    res.json({ success: true });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Błąd serwera' }); }
});

app.get('/api/reports/pending', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM reports WHERE status = $1 ORDER BY id DESC', ['pending']);
    res.json({ reports: result.rows });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Błąd serwera' }); }
});

app.post('/api/reports/:id/status', requireAdmin, async (req, res) => {
  const reportId = parseInt(req.params.id);
  const action = req.body.action;
  try {
    const status = action === 'approve' ? 'approved' : 'rejected';
    await pool.query('UPDATE reports SET status = $1 WHERE id = $2', [status, reportId]);
    res.json({ success: true });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Błąd serwera' }); }
});

// ---------------------------------------------------------
// 💬 KOMUNIKATY
// ---------------------------------------------------------
app.get('/api/messages', requireAuth, async (req, res) => {
  const userId = req.user.id;
  try {
    const result = await pool.query(
      `SELECT m.*, EXISTS(SELECT 1 FROM message_reads r WHERE r."messageId" = m.id AND r."userId" = $1) as "isRead"
       FROM messages m WHERE m."is_global" = true OR m."toId" = $1 ORDER BY m.id DESC LIMIT 50`,
      [userId]
    );
    res.json({ messages: result.rows });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Błąd serwera' }); }
});

app.get('/api/messages/unread-count', requireAuth, async (req, res) => {
  const userId = req.user.id;
  try {
    const result = await pool.query(
      `SELECT COUNT(*) FROM messages m WHERE (m."is_global" = true OR m."toId" = $1) AND NOT EXISTS(SELECT 1 FROM message_reads r WHERE r."messageId" = m.id AND r."userId" = $1)`,
      [userId]
    );
    res.json({ count: parseInt(result.rows[0].count) });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Błąd serwera' }); }
});

app.post('/api/messages/:id/read', requireAuth, async (req, res) => {
  const userId = req.user.id;
  const messageId = parseInt(req.params.id);
  try {
    await pool.query('INSERT INTO message_reads ("messageId", "userId") VALUES ($1,$2) ON CONFLICT DO NOTHING', [messageId, userId]);
    res.json({ success: true });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Błąd serwera' }); }
});

app.post('/api/messages/read-all', requireAuth, async (req, res) => {
  const userId = req.user.id;
  try {
    await pool.query(
      `INSERT INTO message_reads ("messageId", "userId") SELECT m.id, $1 FROM messages m WHERE (m."is_global" = true OR m."toId" = $1) ON CONFLICT DO NOTHING`,
      [userId]
    );
    res.json({ success: true });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Błąd serwera' }); }
});

app.post('/api/messages', requireAdmin, async (req, res) => {
  const { toId, toName, content, isGlobal } = req.body;
  if (!content || !content.trim()) return res.status(400).json({ error: 'Treść komunikatu nie może być pusta' });
  try {
    const id = Date.now();
    await pool.query(
      `INSERT INTO messages (id, "fromId", "fromName", "toId", "toName", content, "is_global") VALUES ($1,$2,$3,$4,$5,$6,$7)`,
      [id, req.user.id, req.user.displayName, isGlobal ? null : toId, isGlobal ? null : toName, content.trim(), !!isGlobal]
    );
    res.json({ success: true });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Błąd serwera' }); }
});

app.delete('/api/messages/:id', requireAdmin, async (req, res) => {
  const messageId = parseInt(req.params.id);
  try {
    await pool.query('DELETE FROM message_reads WHERE "messageId" = $1', [messageId]);
    await pool.query('DELETE FROM messages WHERE id = $1', [messageId]);
    res.json({ success: true });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Błąd serwera' }); }
});

app.get('/api/messages/all', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM messages ORDER BY id DESC LIMIT 100');
    res.json({ messages: result.rows });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Błąd serwera' }); }
});

// ---------------------------------------------------------
// ⚠️ HANDLER BŁĘDÓW
// ---------------------------------------------------------
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) return res.status(400).json({ error: 'Błąd przesyłania pliku: ' + err.message });
  if (err && (err.message === 'Tylko pliki PDF są dozwolone.' || err.message === 'Tylko pliki JPG/PNG są dozwolone.')) return res.status(400).json({ error: err.message });
  if (err && err.message === 'Niedozwolone pochodzenie (CORS)') return res.status(403).json({ error: 'Ta domena nie ma dostępu do API' });
  console.error(err);
  res.status(500).json({ error: 'Wewnętrzny błąd serwera' });
});

// ---------------------------------------------------------
// 🚀 START
// ---------------------------------------------------------
async function startServer() {
  await initDB();
  const adminExists = await pool.query('SELECT id FROM users WHERE login = $1', ['admin']);
  if (adminExists.rows.length === 0) {
    const adminPasswordHash = await bcrypt.hash(ADMIN_PASSWORD, 10);
    await pool.query('INSERT INTO users (id, login, password, role, "displayName") VALUES ($1,$2,$3,$4,$5)', ['admin-1', 'admin', adminPasswordHash, 'admin', 'Centrala vPKM']);
    console.log('✅ Konto admina utworzone');
  }
  app.listen(PORT, () => {
    console.log(`✅ Serwer uruchomiony na porcie: ${PORT}`);
    console.log(`   Dozwolone domeny CORS: ${allowedOrigins.join(', ')}`);
  });
}

startServer();