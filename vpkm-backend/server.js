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

// ---------------------------------------------------------
// 🔑 SEKRETY Z ZMIENNYCH ŚRODOWISKOWYCH
// ---------------------------------------------------------
const SECRET = process.env.JWT_SECRET;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const DATABASE_URL = process.env.DATABASE_URL;

if (!SECRET) {
  console.error('❌ BŁĄD KRYTYCZNY: zmienna środowiskowa JWT_SECRET nie jest ustawiona.');
  process.exit(1);
}
if (!ADMIN_PASSWORD) {
  console.error('❌ BŁĄD KRYTYCZNY: zmienna środowiskowa ADMIN_PASSWORD nie jest ustawiona.');
  process.exit(1);
}
if (!DATABASE_URL) {
  console.error('❌ BŁĄD KRYTYCZNY: zmienna środowiskowa DATABASE_URL nie jest ustawiona.');
  process.exit(1);
}

// ---------------------------------------------------------
// 🗄️ POŁĄCZENIE Z POSTGRESQL
// ---------------------------------------------------------
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ---------------------------------------------------------
// 🏗️ INICJALIZACJA TABEL
// ---------------------------------------------------------
async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      login TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT NOT NULL,
      display_name TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS shifts (
      id BIGINT PRIMARY KEY,
      driver_id TEXT NOT NULL,
      driver_name TEXT NOT NULL,
      line TEXT,
      brigade TEXT,
      bus TEXT,
      start_time TEXT,
      end_time TEXT,
      pdf_url TEXT,
      status TEXT DEFAULT 'active'
    );

    CREATE TABLE IF NOT EXISTS reports (
      id BIGINT PRIMARY KEY,
      driver_id TEXT NOT NULL,
      driver_name TEXT NOT NULL,
      line TEXT,
      date TEXT,
      pdf_url TEXT,
      original_name TEXT,
      status TEXT DEFAULT 'pending'
    );

    CREATE TABLE IF NOT EXISTS fleet (
      id TEXT PRIMARY KEY,
      bus_number TEXT NOT NULL,
      model TEXT NOT NULL,
      assigned_driver_id TEXT DEFAULT '',
      assigned_driver_name TEXT DEFAULT 'Brak'
    );
  `);

  // Domyślny tabor jeśli tabela pusta
  const fleetCount = await pool.query('SELECT COUNT(*) FROM fleet');
  if (parseInt(fleetCount.rows[0].count) === 0) {
    await pool.query(`
      INSERT INTO fleet (id, bus_number, model, assigned_driver_id, assigned_driver_name) VALUES
      ('bus-1', '421', 'Solaris Urbino 18', '', 'Brak'),
      ('bus-2', '105', 'MAN Lion''s City', '', 'Brak')
    `);
  }

  // Konto admina jeśli nie istnieje
  const adminExists = await pool.query("SELECT id FROM users WHERE login = 'admin'");
  if (adminExists.rows.length === 0) {
    const hash = await bcrypt.hash(ADMIN_PASSWORD, 10);
    await pool.query(
      'INSERT INTO users (id, login, password, role, display_name) VALUES ($1, $2, $3, $4, $5)',
      ['admin-1', 'admin', hash, 'admin', 'Centrala vPKM']
    );
    console.log('✅ Konto admina utworzone.');
  }

  console.log('✅ Baza danych gotowa.');
}

// ---------------------------------------------------------
// 🛡️ HELMET
// ---------------------------------------------------------
app.use(helmet());
app.set('trust proxy', 1);

// ---------------------------------------------------------
// 🌐 CORS
// ---------------------------------------------------------
const allowedOrigins = (process.env.FRONTEND_URL || 'http://localhost:5173')
  .split(',')
  .map(s => s.trim().replace(/\/$/, ''))
  .filter(Boolean);

app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      console.warn(`⚠️  Zablokowane zapytanie CORS z pochodzenia: ${origin}`);
      callback(new Error('Niedozwolone pochodzenie (CORS)'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

// ---------------------------------------------------------
// 🚦 RATE LIMITING
// ---------------------------------------------------------
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Za dużo zapytań. Spróbuj ponownie za chwilę.' }
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Za dużo prób logowania. Poczekaj 15 minut.' }
});

app.use(globalLimiter);
app.use(express.json());

// ---------------------------------------------------------
// 📁 MULTER
// ---------------------------------------------------------
const dir = './uploads';
if (!fs.existsSync(dir)) fs.mkdirSync(dir);

const storage = multer.diskStorage({
  destination: function (req, file, cb) { cb(null, 'uploads/'); },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const safeName = file.originalname.replace(/[^a-zA-Z0-9.\-_]/g, '_');
    cb(null, uniqueSuffix + '-' + safeName);
  }
});

const pdfFileFilter = (req, file, cb) => {
  const isPdfMime = file.mimetype === 'application/pdf';
  const isPdfExt = path.extname(file.originalname).toLowerCase() === '.pdf';
  if (isPdfMime && isPdfExt) {
    cb(null, true);
  } else {
    cb(new Error('Tylko pliki PDF są dozwolone.'));
  }
};

const upload = multer({
  storage: storage,
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: pdfFileFilter
});

// ---------------------------------------------------------
// 🔐 MIDDLEWARE AUTORYZACJI JWT
// ---------------------------------------------------------
const requireAuth = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Brak tokenu autoryzacji' });
  }
  const token = authHeader.split(' ')[1];
  try {
    req.user = jwt.verify(token, SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Token nieprawidłowy lub wygasł' });
  }
};

const requireAdmin = (req, res, next) => {
  requireAuth(req, res, () => {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Brak uprawnień administratora' });
    }
    next();
  });
};

// ---------------------------------------------------------
// 🚀 ENDPOINTY PUBLICZNE
// ---------------------------------------------------------
app.get('/', (req, res) => {
  res.send('Serwer vPKM działa poprawnie!');
});

app.post('/api/login', loginLimiter, async (req, res) => {
  const { login, password } = req.body;
  const result = await pool.query('SELECT * FROM users WHERE login = $1', [login]);
  const user = result.rows[0];

  if (!user) {
    return res.status(401).json({ success: false, message: 'Błędny login lub hasło!' });
  }

  const passwordMatch = await bcrypt.compare(password, user.password);
  if (!passwordMatch) {
    return res.status(401).json({ success: false, message: 'Błędny login lub hasło!' });
  }

  const token = jwt.sign(
    { id: user.id, role: user.role, displayName: user.display_name },
    SECRET,
    { expiresIn: '8h' }
  );

  res.json({
    success: true,
    user: { id: user.id, login: user.login, role: user.role, displayName: user.display_name },
    token
  });
});

// ---------------------------------------------------------
// 🚀 ENDPOINTY CHRONIONE — KIEROWCA I ADMIN
// ---------------------------------------------------------
app.get('/api/drivers', requireAuth, async (req, res) => {
  const result = await pool.query(
    "SELECT id, display_name, login FROM users WHERE role = 'driver'"
  );
  res.json(result.rows.map(d => ({
    id: d.id,
    displayName: d.display_name,
    login: d.login
  })));
});

app.get('/api/shifts/:driverId', requireAuth, async (req, res) => {
  if (req.user.role === 'driver' && req.user.id !== req.params.driverId) {
    return res.status(403).json({ error: 'Możesz sprawdzać tylko swoją służbę' });
  }
  const result = await pool.query(
    "SELECT * FROM shifts WHERE driver_id = $1 AND status = 'active'",
    [req.params.driverId]
  );
  const s = result.rows[0];
  if (!s) return res.json({ shift: null });

  res.json({
    shift: {
      id: s.id, driverId: s.driver_id, driverName: s.driver_name,
      line: s.line, brigade: s.brigade, bus: s.bus,
      startTime: s.start_time, endTime: s.end_time,
      pdfUrl: s.pdf_url, status: s.status
    }
  });
});

app.post('/api/reports', requireAuth, upload.single('report_pdf'), async (req, res) => {
  const file = req.file;
  if (!file) return res.status(400).json({ error: 'Brak pliku PDF!' });

  const id = Date.now();
  const pdfUrl = `/api/files/${file.filename}`;

  await pool.query(
    'INSERT INTO reports (id, driver_id, driver_name, line, date, pdf_url, original_name, status) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)',
    [id, req.body.driverId, req.body.driverName, req.body.line,
     new Date().toLocaleString('pl-PL'), pdfUrl, file.originalname, 'pending']
  );

  await pool.query(
    "UPDATE shifts SET status = 'completed' WHERE driver_id = $1 AND status = 'active'",
    [req.body.driverId]
  );

  res.json({ success: true });
});

app.get('/api/fleet', requireAuth, async (req, res) => {
  const result = await pool.query('SELECT * FROM fleet ORDER BY bus_number');
  res.json(result.rows.map(b => ({
    id: b.id, busNumber: b.bus_number, model: b.model,
    assignedDriverId: b.assigned_driver_id,
    assignedDriverName: b.assigned_driver_name
  })));
});

// ---------------------------------------------------------
// 📥 CHRONIONY DOSTĘP DO PLIKÓW
// ---------------------------------------------------------
app.get('/api/files/:filename', requireAuth, async (req, res) => {
  const filename = req.params.filename;

  if (filename.includes('..') || filename.includes('/') || filename.includes('\\')) {
    return res.status(400).json({ error: 'Nieprawidłowa nazwa pliku' });
  }

  const filePath = path.join(__dirname, 'uploads', filename);
  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ error: 'Plik nie istnieje' });
  }

  if (req.user.role === 'admin') {
    return res.sendFile(filePath);
  }

  const relativeUrl = `/api/files/${filename}`;
  const shiftRes = await pool.query(
    'SELECT id FROM shifts WHERE pdf_url = $1 AND driver_id = $2',
    [relativeUrl, req.user.id]
  );
  const reportRes = await pool.query(
    'SELECT id FROM reports WHERE pdf_url = $1 AND driver_id = $2',
    [relativeUrl, req.user.id]
  );

  if (shiftRes.rows.length > 0 || reportRes.rows.length > 0) {
    return res.sendFile(filePath);
  }

  return res.status(403).json({ error: 'Brak dostępu do tego pliku' });
});

// ---------------------------------------------------------
// 🚀 ENDPOINTY CHRONIONE — TYLKO ADMIN
// ---------------------------------------------------------
app.post('/api/fleet', requireAdmin, async (req, res) => {
  const { busNumber, model, assignedDriverId, assignedDriverName } = req.body;
  const id = 'bus-' + Date.now();

  await pool.query(
    'INSERT INTO fleet (id, bus_number, model, assigned_driver_id, assigned_driver_name) VALUES ($1,$2,$3,$4,$5)',
    [id, busNumber, model, assignedDriverId || '', assignedDriverName || 'Brak']
  );

  res.json({ success: true, vehicle: { id, busNumber, model, assignedDriverId, assignedDriverName } });
});

app.put('/api/fleet/:id', requireAdmin, async (req, res) => {
  const { busNumber, model, assignedDriverId, assignedDriverName } = req.body;

  const result = await pool.query(
    'UPDATE fleet SET bus_number=$1, model=$2, assigned_driver_id=$3, assigned_driver_name=$4 WHERE id=$5 RETURNING *',
    [busNumber, model, assignedDriverId || '', assignedDriverName || 'Brak', req.params.id]
  );

  if (result.rows.length === 0) {
    return res.status(404).json({ error: 'Nie znaleziono takiego pojazdu w bazie taboru!' });
  }

  const b = result.rows[0];
  res.json({ success: true, vehicle: {
    id: b.id, busNumber: b.bus_number, model: b.model,
    assignedDriverId: b.assigned_driver_id, assignedDriverName: b.assigned_driver_name
  }});
});

app.delete('/api/fleet/:id', requireAdmin, async (req, res) => {
  await pool.query('DELETE FROM fleet WHERE id = $1', [req.params.id]);
  res.json({ success: true });
});

app.post('/api/drivers', requireAdmin, async (req, res) => {
  const { login, password, displayName } = req.body;

  const exists = await pool.query('SELECT id FROM users WHERE login = $1', [login]);
  if (exists.rows.length > 0) {
    return res.status(400).json({ success: false, message: 'Ten login jest już zajęty!' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const id = 'driver-' + Date.now();

  await pool.query(
    'INSERT INTO users (id, login, password, role, display_name) VALUES ($1,$2,$3,$4,$5)',
    [id, login, hashedPassword, 'driver', displayName]
  );

  res.json({ success: true, driver: { id, login, role: 'driver', displayName } });
});

app.post('/api/shifts', requireAdmin, upload.single('pdf_file'), async (req, res) => {
  const data = req.body;
  const file = req.file;

  await pool.query(
    "UPDATE shifts SET status = 'cancelled' WHERE driver_id = $1 AND status = 'active'",
    [data.driverId]
  );

  const id = Date.now();
  const pdfUrl = file ? `/api/files/${file.filename}` : null;

  await pool.query(
    'INSERT INTO shifts (id, driver_id, driver_name, line, brigade, bus, start_time, end_time, pdf_url, status) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)',
    [id, data.driverId, data.driverName, data.line, data.brigade,
     data.bus, data.startTime, data.endTime, pdfUrl, 'active']
  );

  res.json({ success: true, shift: { id, ...data, pdfUrl, status: 'active' } });
});

app.get('/api/shifts', requireAdmin, async (req, res) => {
  const result = await pool.query("SELECT * FROM shifts WHERE status = 'active'");
  res.json({
    shifts: result.rows.map(s => ({
      id: s.id, driverId: s.driver_id, driverName: s.driver_name,
      line: s.line, brigade: s.brigade, bus: s.bus,
      startTime: s.start_time, endTime: s.end_time,
      pdfUrl: s.pdf_url, status: s.status
    }))
  });
});

app.delete('/api/shifts/:driverId', requireAdmin, async (req, res) => {
  await pool.query('DELETE FROM shifts WHERE driver_id = $1', [req.params.driverId]);
  res.json({ success: true });
});

app.get('/api/reports/pending', requireAdmin, async (req, res) => {
  const result = await pool.query("SELECT * FROM reports WHERE status = 'pending' ORDER BY id DESC");
  res.json({
    reports: result.rows.map(r => ({
      id: r.id, driverId: r.driver_id, driverName: r.driver_name,
      line: r.line, date: r.date, pdfUrl: r.pdf_url,
      originalName: r.original_name, status: r.status
    }))
  });
});

app.post('/api/reports/:id/status', requireAdmin, async (req, res) => {
  const action = req.body.action;
  const status = action === 'approve' ? 'approved' : 'rejected';

  const result = await pool.query(
    'UPDATE reports SET status = $1 WHERE id = $2 RETURNING id',
    [status, req.params.id]
  );

  if (result.rows.length === 0) {
    return res.status(404).json({ error: 'Nie znaleziono raportu' });
  }

  res.json({ success: true });
});

// ---------------------------------------------------------
// ⚠️ CENTRALNY HANDLER BŁĘDÓW
// ---------------------------------------------------------
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    return res.status(400).json({ error: 'Błąd przesyłania pliku: ' + err.message });
  }
  if (err && err.message === 'Tylko pliki PDF są dozwolone.') {
    return res.status(400).json({ error: err.message });
  }
  if (err && err.message === 'Niedozwolone pochodzenie (CORS)') {
    return res.status(403).json({ error: 'Ta domena nie ma dostępu do API' });
  }
  console.error(err);
  res.status(500).json({ error: 'Wewnętrzny błąd serwera' });
});

// ---------------------------------------------------------
// 🚀 START SERWERA
// ---------------------------------------------------------
async function startServer() {
  await initDb();

  app.listen(PORT, () => {
    console.log(`✅ Serwer uruchomiony na porcie: ${PORT}`);
    console.log(`   Dozwolone domeny CORS: ${allowedOrigins.join(', ')}`);
  });
}

startServer();