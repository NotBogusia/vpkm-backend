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
const DATABASE_URL = process.env.DATABASE_URL;

if (!SECRET) { console.error('❌ BŁĄD: JWT_SECRET nie ustawiony.'); process.exit(1); }
if (!ADMIN_PASSWORD) { console.error('❌ BŁĄD: ADMIN_PASSWORD nie ustawiony.'); process.exit(1); }
if (!DATABASE_URL) { console.error('❌ BŁĄD: DATABASE_URL nie ustawiony.'); process.exit(1); }

const pool = new Pool({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false } });

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
      line TEXT, brigade TEXT, bus TEXT,
      start_time TEXT, end_time TEXT,
      pdf_url TEXT,
      status TEXT DEFAULT 'active'
    );

    CREATE TABLE IF NOT EXISTS reports (
      id BIGINT PRIMARY KEY,
      driver_id TEXT NOT NULL,
      driver_name TEXT NOT NULL,
      line TEXT, date TEXT, pdf_url TEXT,
      original_name TEXT,
      status TEXT DEFAULT 'pending'
    );

    CREATE TABLE IF NOT EXISTS fleet (
      id TEXT PRIMARY KEY,
      bus_number TEXT NOT NULL,
      model TEXT NOT NULL,
      assigned_driver_id TEXT DEFAULT '',
      assigned_driver_name TEXT DEFAULT 'Brak',
      brand TEXT DEFAULT '',
      vehicle_type TEXT DEFAULT '',
      fleet_type TEXT DEFAULT '',
      status TEXT DEFAULT 'sprawny',
      year_manufactured TEXT DEFAULT '',
      registration_number TEXT DEFAULT '',
      notes TEXT DEFAULT ''
    );

    CREATE TABLE IF NOT EXISTS messages (
      id BIGINT PRIMARY KEY,
      from_id TEXT NOT NULL,
      from_name TEXT NOT NULL,
      to_id TEXT,
      to_name TEXT,
      content TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      is_global BOOLEAN DEFAULT FALSE
    );

    CREATE TABLE IF NOT EXISTS message_reads (
      message_id BIGINT NOT NULL,
      user_id TEXT NOT NULL,
      PRIMARY KEY (message_id, user_id)
    );
  `);

  // Migracje fleet
  await pool.query(`
    DO $$
    BEGIN
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='fleet' AND column_name='brand') THEN ALTER TABLE fleet ADD COLUMN brand TEXT DEFAULT ''; END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='fleet' AND column_name='vehicle_type') THEN ALTER TABLE fleet ADD COLUMN vehicle_type TEXT DEFAULT ''; END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='fleet' AND column_name='fleet_type') THEN ALTER TABLE fleet ADD COLUMN fleet_type TEXT DEFAULT ''; END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='fleet' AND column_name='status') THEN ALTER TABLE fleet ADD COLUMN status TEXT DEFAULT 'sprawny'; END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='fleet' AND column_name='year_manufactured') THEN ALTER TABLE fleet ADD COLUMN year_manufactured TEXT DEFAULT ''; END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='fleet' AND column_name='registration_number') THEN ALTER TABLE fleet ADD COLUMN registration_number TEXT DEFAULT ''; END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='fleet' AND column_name='notes') THEN ALTER TABLE fleet ADD COLUMN notes TEXT DEFAULT ''; END IF;
    END$$;
  `);

  const fleetCount = await pool.query('SELECT COUNT(*) FROM fleet');
  if (parseInt(fleetCount.rows[0].count) === 0) {
    await pool.query(`
      INSERT INTO fleet (id, bus_number, model, assigned_driver_id, assigned_driver_name, brand, vehicle_type, fleet_type, status, year_manufactured, registration_number, notes) VALUES
      ('bus-1', '421', 'Urbino 18', '', 'Brak', 'Solaris', 'Autobus przegubowy', 'miejski', 'sprawny', '2019', 'SY 12345', ''),
      ('bus-2', '105', 'Lion''s City', '', 'Brak', 'MAN', 'Autobus standardowy', 'miejski', 'sprawny', '2017', 'SY 67890', '')
    `);
  }

  const adminExists = await pool.query("SELECT id FROM users WHERE login = 'admin'");
  if (adminExists.rows.length === 0) {
    const hash = await bcrypt.hash(ADMIN_PASSWORD, 10);
    await pool.query('INSERT INTO users (id, login, password, role, display_name) VALUES ($1,$2,$3,$4,$5)', ['admin-1', 'admin', hash, 'admin', 'Centrala vPKM']);
    console.log('✅ Konto admina utworzone.');
  }

  console.log('✅ Baza danych gotowa.');
}

app.use(helmet());
app.set('trust proxy', 1);

const allowedOrigins = (process.env.FRONTEND_URL || 'http://localhost:5173')
  .split(',').map(s => s.trim().replace(/\/$/, '')).filter(Boolean);

app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) { callback(null, true); }
    else { callback(new Error('Niedozwolone pochodzenie (CORS)')); }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

const globalLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 2000, standardHeaders: true, legacyHeaders: false, message: { error: 'Za dużo zapytań.' } });
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 50, standardHeaders: true, legacyHeaders: false, message: { error: 'Za dużo prób logowania.' } });

app.use(globalLimiter);
app.use(express.json());

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
  if (file.mimetype === 'application/pdf' && path.extname(file.originalname).toLowerCase() === '.pdf') { cb(null, true); }
  else { cb(new Error('Tylko pliki PDF są dozwolone.')); }
};

const upload = multer({ storage, limits: { fileSize: 10 * 1024 * 1024 }, fileFilter: pdfFileFilter });

const requireAuth = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ error: 'Brak tokenu' });
  try { req.user = jwt.verify(authHeader.split(' ')[1], SECRET); next(); }
  catch { return res.status(401).json({ error: 'Token nieprawidłowy lub wygasł' }); }
};

const requireAdmin = (req, res, next) => {
  requireAuth(req, res, () => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Brak uprawnień' });
    next();
  });
};

// ---------------------------------------------------------
// ENDPOINTY PUBLICZNE
// ---------------------------------------------------------
app.get('/', (req, res) => res.send('Serwer vPKM działa poprawnie!'));

app.post('/api/login', loginLimiter, async (req, res) => {
  try {
    const { login, password } = req.body;
    if (!login || !password) return res.status(400).json({ success: false, message: 'Podaj login i hasło.' });
    const result = await pool.query('SELECT * FROM users WHERE login = $1', [login]);
    const user = result.rows[0];
    if (!user) return res.status(401).json({ success: false, message: 'Błędny login lub hasło!' });
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) return res.status(401).json({ success: false, message: 'Błędny login lub hasło!' });
    const token = jwt.sign({ id: user.id, role: user.role, displayName: user.display_name }, SECRET, { expiresIn: '8h' });
    res.json({ success: true, user: { id: user.id, login: user.login, role: user.role, displayName: user.display_name }, token });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ success: false, message: 'Błąd serwera.' });
  }
});

// ---------------------------------------------------------
// ENDPOINTY CHRONIONE — KIEROWCA I ADMIN
// ---------------------------------------------------------
app.get('/api/drivers', requireAuth, async (req, res) => {
  const result = await pool.query("SELECT id, display_name, login FROM users WHERE role = 'driver'");
  res.json(result.rows.map(d => ({ id: d.id, displayName: d.display_name, login: d.login })));
});

app.get('/api/shifts/history/:driverId', requireAuth, async (req, res) => {
  if (req.user.role === 'driver' && req.user.id !== req.params.driverId) return res.status(403).json({ error: 'Brak dostępu' });
  const result = await pool.query("SELECT * FROM shifts WHERE driver_id = $1 AND status != 'active' ORDER BY id DESC LIMIT 20", [req.params.driverId]);
  res.json({ history: result.rows.map(s => ({ id: s.id, driverName: s.driver_name, line: s.line, brigade: s.brigade, bus: s.bus, startTime: s.start_time, endTime: s.end_time, status: s.status })) });
});

app.get('/api/shifts/:driverId', requireAuth, async (req, res) => {
  if (req.user.role === 'driver' && req.user.id !== req.params.driverId) return res.status(403).json({ error: 'Możesz sprawdzać tylko swoją służbę' });
  const result = await pool.query("SELECT * FROM shifts WHERE driver_id = $1 AND status = 'active'", [req.params.driverId]);
  const s = result.rows[0];
  if (!s) return res.json({ shift: null });
  res.json({ shift: { id: s.id, driverId: s.driver_id, driverName: s.driver_name, line: s.line, brigade: s.brigade, bus: s.bus, startTime: s.start_time, endTime: s.end_time, pdfUrl: s.pdf_url, status: s.status } });
});

app.post('/api/reports', requireAuth, upload.single('report_pdf'), async (req, res) => {
  const file = req.file;
  if (!file) return res.status(400).json({ error: 'Brak pliku PDF!' });
  const id = Date.now();
  const pdfUrl = `/api/files/${file.filename}`;
  await pool.query('INSERT INTO reports (id, driver_id, driver_name, line, date, pdf_url, original_name, status) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)', [id, req.body.driverId, req.body.driverName, req.body.line, new Date().toLocaleString('pl-PL'), pdfUrl, file.originalname, 'pending']);
  await pool.query("UPDATE shifts SET status = 'completed' WHERE driver_id = $1 AND status = 'active'", [req.body.driverId]);
  res.json({ success: true });
});

// ---------------------------------------------------------
// 💬 KOMUNIKATY
// ---------------------------------------------------------

// Pobierz komunikaty dla zalogowanego użytkownika (swoje + globalne)
app.get('/api/messages', requireAuth, async (req, res) => {
  const userId = req.user.id;
  // Pobieramy wiadomości: globalne LUB skierowane do tego użytkownika
  // + info czy przeczytane
  const result = await pool.query(`
    SELECT 
      m.*,
      CASE WHEN mr.user_id IS NOT NULL THEN TRUE ELSE FALSE END AS is_read
    FROM messages m
    LEFT JOIN message_reads mr ON mr.message_id = m.id AND mr.user_id = $1
    WHERE m.is_global = TRUE OR m.to_id = $1
    ORDER BY m.created_at DESC
    LIMIT 50
  `, [userId]);

  res.json({ messages: result.rows.map(m => ({
    id: m.id,
    fromId: m.from_id,
    fromName: m.from_name,
    toId: m.to_id,
    toName: m.to_name,
    content: m.content,
    createdAt: m.created_at,
    isGlobal: m.is_global,
    isRead: m.is_read
  }))});
});

// Policz nieodczytane komunikaty
app.get('/api/messages/unread-count', requireAuth, async (req, res) => {
  const userId = req.user.id;
  const result = await pool.query(`
    SELECT COUNT(*) FROM messages m
    LEFT JOIN message_reads mr ON mr.message_id = m.id AND mr.user_id = $1
    WHERE (m.is_global = TRUE OR m.to_id = $1)
    AND mr.user_id IS NULL
  `, [userId]);
  res.json({ count: parseInt(result.rows[0].count) });
});

// Oznacz komunikat jako przeczytany
app.post('/api/messages/:id/read', requireAuth, async (req, res) => {
  const userId = req.user.id;
  const messageId = req.params.id;
  await pool.query('INSERT INTO message_reads (message_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING', [messageId, userId]);
  res.json({ success: true });
});

// Oznacz wszystkie jako przeczytane
app.post('/api/messages/read-all', requireAuth, async (req, res) => {
  const userId = req.user.id;
  // Pobieramy id wszystkich wiadomości dla tego użytkownika i wstawiamy odczyty
  await pool.query(`
    INSERT INTO message_reads (message_id, user_id)
    SELECT m.id, $1 FROM messages m
    WHERE (m.is_global = TRUE OR m.to_id = $1)
    ON CONFLICT DO NOTHING
  `, [userId]);
  res.json({ success: true });
});

// Admin: wyślij komunikat
app.post('/api/messages', requireAdmin, async (req, res) => {
  const { toId, toName, content, isGlobal } = req.body;
  if (!content || !content.trim()) return res.status(400).json({ error: 'Treść komunikatu nie może być pusta' });

  const id = Date.now();
  await pool.query(
    'INSERT INTO messages (id, from_id, from_name, to_id, to_name, content, is_global) VALUES ($1,$2,$3,$4,$5,$6,$7)',
    [id, req.user.id, req.user.displayName, isGlobal ? null : toId, isGlobal ? null : toName, content.trim(), isGlobal ? true : false]
  );

  res.json({ success: true });
});

// Admin: usuń komunikat
app.delete('/api/messages/:id', requireAdmin, async (req, res) => {
  await pool.query('DELETE FROM message_reads WHERE message_id = $1', [req.params.id]);
  await pool.query('DELETE FROM messages WHERE id = $1', [req.params.id]);
  res.json({ success: true });
});

// Admin: lista wszystkich komunikatów
app.get('/api/messages/all', requireAdmin, async (req, res) => {
  const result = await pool.query('SELECT * FROM messages ORDER BY created_at DESC LIMIT 100');
  res.json({ messages: result.rows.map(m => ({
    id: m.id, fromId: m.from_id, fromName: m.from_name,
    toId: m.to_id, toName: m.to_name,
    content: m.content, createdAt: m.created_at, isGlobal: m.is_global
  }))});
});

// ---------------------------------------------------------
// FLEET
// ---------------------------------------------------------
const mapFleetRow = (b) => ({ id: b.id, busNumber: b.bus_number, model: b.model, assignedDriverId: b.assigned_driver_id, assignedDriverName: b.assigned_driver_name, brand: b.brand || '', vehicleType: b.vehicle_type || '', fleetType: b.fleet_type || '', status: b.status || 'sprawny', yearManufactured: b.year_manufactured || '', registrationNumber: b.registration_number || '', notes: b.notes || '' });

app.get('/api/fleet', requireAuth, async (req, res) => {
  const result = await pool.query('SELECT * FROM fleet ORDER BY bus_number');
  res.json(result.rows.map(mapFleetRow));
});

// ZMIANA HASŁA
app.post('/api/change-password', requireAuth, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!newPassword || newPassword.length < 6) return res.status(400).json({ error: 'Nowe hasło musi mieć minimum 6 znaków' });
  const result = await pool.query('SELECT * FROM users WHERE id = $1', [req.user.id]);
  const user = result.rows[0];
  if (!user) return res.status(404).json({ error: 'Nie znaleziono użytkownika' });
  const passwordMatch = await bcrypt.compare(currentPassword, user.password);
  if (!passwordMatch) return res.status(401).json({ error: 'Obecne hasło jest nieprawidłowe' });
  const hashedPassword = await bcrypt.hash(newPassword, 10);
  await pool.query('UPDATE users SET password = $1 WHERE id = $2', [hashedPassword, req.user.id]);
  res.json({ success: true });
});

// CHRONIONY DOSTĘP DO PLIKÓW
app.get('/api/files/:filename', requireAuth, async (req, res) => {
  const filename = req.params.filename;
  if (filename.includes('..') || filename.includes('/') || filename.includes('\\')) return res.status(400).json({ error: 'Nieprawidłowa nazwa pliku' });
  const filePath = path.join(__dirname, 'uploads', filename);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'Plik nie istnieje' });
  if (req.user.role === 'admin') return res.sendFile(filePath);
  const relativeUrl = `/api/files/${filename}`;
  const shiftRes = await pool.query('SELECT id FROM shifts WHERE pdf_url = $1 AND driver_id = $2', [relativeUrl, req.user.id]);
  const reportRes = await pool.query('SELECT id FROM reports WHERE pdf_url = $1 AND driver_id = $2', [relativeUrl, req.user.id]);
  if (shiftRes.rows.length > 0 || reportRes.rows.length > 0) return res.sendFile(filePath);
  return res.status(403).json({ error: 'Brak dostępu do tego pliku' });
});

// ---------------------------------------------------------
// ENDPOINTY TYLKO ADMIN
// ---------------------------------------------------------
app.post('/api/fleet', requireAdmin, async (req, res) => {
  const { busNumber, model, assignedDriverId, assignedDriverName, brand, vehicleType, fleetType, status, yearManufactured, registrationNumber, notes } = req.body;
  const id = 'bus-' + Date.now();
  await pool.query('INSERT INTO fleet (id, bus_number, model, assigned_driver_id, assigned_driver_name, brand, vehicle_type, fleet_type, status, year_manufactured, registration_number, notes) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)', [id, busNumber, model, assignedDriverId || '', assignedDriverName || 'Brak', brand || '', vehicleType || '', fleetType || '', status || 'sprawny', yearManufactured || '', registrationNumber || '', notes || '']);
  const result = await pool.query('SELECT * FROM fleet WHERE id = $1', [id]);
  res.json({ success: true, vehicle: mapFleetRow(result.rows[0]) });
});

app.put('/api/fleet/:id', requireAdmin, async (req, res) => {
  const { busNumber, model, assignedDriverId, assignedDriverName, brand, vehicleType, fleetType, status, yearManufactured, registrationNumber, notes } = req.body;
  const result = await pool.query('UPDATE fleet SET bus_number=$1, model=$2, assigned_driver_id=$3, assigned_driver_name=$4, brand=$5, vehicle_type=$6, fleet_type=$7, status=$8, year_manufactured=$9, registration_number=$10, notes=$11 WHERE id=$12 RETURNING *', [busNumber, model, assignedDriverId || '', assignedDriverName || 'Brak', brand || '', vehicleType || '', fleetType || '', status || 'sprawny', yearManufactured || '', registrationNumber || '', notes || '', req.params.id]);
  if (result.rows.length === 0) return res.status(404).json({ error: 'Nie znaleziono pojazdu' });
  res.json({ success: true, vehicle: mapFleetRow(result.rows[0]) });
});

app.delete('/api/fleet/:id', requireAdmin, async (req, res) => {
  await pool.query('DELETE FROM fleet WHERE id = $1', [req.params.id]);
  res.json({ success: true });
});

app.post('/api/drivers', requireAdmin, async (req, res) => {
  const { login, password, displayName } = req.body;
  const exists = await pool.query('SELECT id FROM users WHERE login = $1', [login]);
  if (exists.rows.length > 0) return res.status(400).json({ success: false, message: 'Ten login jest już zajęty!' });
  const hashedPassword = await bcrypt.hash(password, 10);
  const id = 'driver-' + Date.now();
  await pool.query('INSERT INTO users (id, login, password, role, display_name) VALUES ($1,$2,$3,$4,$5)', [id, login, hashedPassword, 'driver', displayName]);
  res.json({ success: true, driver: { id, login, role: 'driver', displayName } });
});

app.get('/api/shifts', requireAdmin, async (req, res) => {
  const result = await pool.query("SELECT * FROM shifts WHERE status = 'active'");
  res.json({ shifts: result.rows.map(s => ({ id: s.id, driverId: s.driver_id, driverName: s.driver_name, line: s.line, brigade: s.brigade, bus: s.bus, startTime: s.start_time, endTime: s.end_time, pdfUrl: s.pdf_url, status: s.status })) });
});

app.post('/api/shifts', requireAdmin, upload.single('pdf_file'), async (req, res) => {
  const data = req.body;
  const file = req.file;
  await pool.query("UPDATE shifts SET status = 'cancelled' WHERE driver_id = $1 AND status = 'active'", [data.driverId]);
  const id = Date.now();
  const pdfUrl = file ? `/api/files/${file.filename}` : null;
  await pool.query('INSERT INTO shifts (id, driver_id, driver_name, line, brigade, bus, start_time, end_time, pdf_url, status) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)', [id, data.driverId, data.driverName, data.line, data.brigade, data.bus, data.startTime, data.endTime, pdfUrl, 'active']);
  res.json({ success: true, shift: { id, ...data, pdfUrl, status: 'active' } });
});

app.delete('/api/shifts/:driverId', requireAdmin, async (req, res) => {
  await pool.query('DELETE FROM shifts WHERE driver_id = $1', [req.params.driverId]);
  res.json({ success: true });
});

app.delete('/api/drivers/:id', requireAdmin, async (req, res) => {
  const { id } = req.params;
  await pool.query('DELETE FROM shifts WHERE driver_id = $1', [id]);
  await pool.query('DELETE FROM reports WHERE driver_id = $1', [id]);
  await pool.query('UPDATE fleet SET assigned_driver_id = $1, assigned_driver_name = $2 WHERE assigned_driver_id = $3', ['', 'Brak', id]);
  const result = await pool.query('DELETE FROM users WHERE id = $1 RETURNING id', [id]);
  if (result.rows.length === 0) return res.status(404).json({ error: 'Nie znaleziono kierowcy' });
  res.json({ success: true });
});

app.get('/api/reports/pending', requireAdmin, async (req, res) => {
  const result = await pool.query("SELECT * FROM reports WHERE status = 'pending' ORDER BY id DESC");
  res.json({ reports: result.rows.map(r => ({ id: r.id, driverId: r.driver_id, driverName: r.driver_name, line: r.line, date: r.date, pdfUrl: r.pdf_url, originalName: r.original_name, status: r.status })) });
});

app.post('/api/reports/:id/status', requireAdmin, async (req, res) => {
  const status = req.body.action === 'approve' ? 'approved' : 'rejected';
  const result = await pool.query('UPDATE reports SET status = $1 WHERE id = $2 RETURNING id', [status, req.params.id]);
  if (result.rows.length === 0) return res.status(404).json({ error: 'Nie znaleziono raportu' });
  res.json({ success: true });
});

// HANDLER BŁĘDÓW
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) return res.status(400).json({ error: 'Błąd przesyłania: ' + err.message });
  if (err?.message === 'Tylko pliki PDF są dozwolone.') return res.status(400).json({ error: err.message });
  if (err?.message === 'Niedozwolone pochodzenie (CORS)') return res.status(403).json({ error: 'Brak dostępu' });
  console.error(err);
  res.status(500).json({ error: 'Wewnętrzny błąd serwera' });
});

async function startServer() {
  await initDb();
  app.listen(PORT, () => {
    console.log(`✅ Serwer uruchomiony na porcie: ${PORT}`);
    console.log(`   Dozwolone domeny CORS: ${allowedOrigins.join(', ')}`);
  });
}

startServer();