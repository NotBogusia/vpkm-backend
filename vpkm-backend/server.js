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
// 🔑 SEKRETY
// ---------------------------------------------------------
const SECRET = process.env.JWT_SECRET;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

if (!SECRET) { console.error('❌ Brak JWT_SECRET'); process.exit(1); }
if (!ADMIN_PASSWORD) { console.error('❌ Brak ADMIN_PASSWORD'); process.exit(1); }

// ---------------------------------------------------------
// 🗄️ POSTGRESQL
// ---------------------------------------------------------
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ---------------------------------------------------------
// 🛡️ HELMET + TRUST PROXY
// ---------------------------------------------------------
app.use(helmet({
  crossOriginResourcePolicy: { policy: 'cross-origin' }
}));
app.set('trust proxy', 1);

// ---------------------------------------------------------
// 🌐 CORS
// ---------------------------------------------------------
const allowedOrigins = (process.env.FRONTEND_URL || 'http://localhost:5173')
  .split(',').map(s => s.trim()).filter(Boolean);

app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) { callback(null, true); }
    else {
      console.warn(`⚠️ Zablokowane CORS z: ${origin}`);
      callback(new Error('Niedozwolone pochodzenie (CORS)'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

// ---------------------------------------------------------
// 🚦 RATE LIMITING
// ---------------------------------------------------------
const globalLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 1000, standardHeaders: true, legacyHeaders: false, message: { error: 'Za dużo zapytań.' } });
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100, standardHeaders: true, legacyHeaders: false, message: { error: 'Za dużo prób logowania. Poczekaj 15 minut.' } });

app.use(globalLimiter);
app.use(express.json());

// ---------------------------------------------------------
// 📁 FOLDERY
// ---------------------------------------------------------
const dir = './uploads';
if (!fs.existsSync(dir)) fs.mkdirSync(dir);
const plateDir = './uploads/plates';
if (!fs.existsSync(plateDir)) fs.mkdirSync(plateDir, { recursive: true });

// ---------------------------------------------------------
// 📁 MULTER — PDF
// ---------------------------------------------------------
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const safeName = file.originalname.replace(/[^a-zA-Z0-9.\-_]/g, '_');
    cb(null, uniqueSuffix + '-' + safeName);
  }
});
const pdfFileFilter = (req, file, cb) => {
  const isPdfMime = file.mimetype === 'application/pdf';
  const isPdfExt = path.extname(file.originalname).toLowerCase() === '.pdf';
  if (isPdfMime && isPdfExt) cb(null, true);
  else cb(new Error('Tylko pliki PDF są dozwolone.'));
};
const upload = multer({ storage, limits: { fileSize: 10 * 1024 * 1024 }, fileFilter: pdfFileFilter });

// ---------------------------------------------------------
// 📁 MULTER — zdjęcia tablic
// ---------------------------------------------------------
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

// ---------------------------------------------------------
// 🔐 AUTORYZACJA JWT
// ---------------------------------------------------------
const requireAuth = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ error: 'Brak tokenu autoryzacji' });
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
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Brak uprawnień administratora' });
    next();
  });
};

// ---------------------------------------------------------
// 🗄️ RAM — służby, raporty, wiadomości (nie wymagają trwałości)
// ---------------------------------------------------------
let shifts = [];
let reports = [];
let messages = [];
let messageReads = [];

// ---------------------------------------------------------
// 🗄️ INICJALIZACJA BAZY DANYCH
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
    const token = jwt.sign({ id: user.id, role: user.role, displayName: user.displayName }, SECRET, { expiresIn: '8h' });
    const { password: _, ...safeUser } = user;
    res.json({ success: true, user: safeUser, token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Błąd serwera' });
  }
});

// ---------------------------------------------------------
// 🚀 ENDPOINTY CHRONIONE — KIEROWCA I ADMIN
// ---------------------------------------------------------
app.get('/api/drivers', requireAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, login, "displayName" FROM users WHERE role = $1', ['driver']);
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Błąd serwera' });
  }
});

app.get('/api/shifts/:driverId', requireAuth, (req, res) => {
  if (req.user.role === 'driver' && req.user.id !== req.params.driverId) {
    return res.status(403).json({ error: 'Możesz sprawdzać tylko swoją służbę' });
  }
  const myShift = shifts.find(s => s.driverId === req.params.driverId && s.status === 'active');
  res.json({ shift: myShift || null });
});

app.get('/api/shifts/history/:driverId', requireAuth, (req, res) => {
  if (req.user.role === 'driver' && req.user.id !== req.params.driverId) {
    return res.status(403).json({ error: 'Brak dostępu' });
  }
  const history = shifts.filter(s => s.driverId === req.params.driverId && s.status !== 'active').slice(-20).reverse();
  res.json({ history });
});

app.post('/api/reports', requireAuth, upload.single('report_pdf'), (req, res) => {
  const file = req.file;
  if (!file) return res.status(400).json({ error: 'Brak pliku PDF!' });
  const newReport = {
    id: Date.now(),
    driverId: req.body.driverId,
    driverName: req.body.driverName,
    line: req.body.line,
    date: new Date().toLocaleString('pl-PL'),
    pdfUrl: `/api/files/${file.filename}`,
    originalName: file.originalname,
    status: 'pending'
  };
  const shiftIndex = shifts.findIndex(s => s.driverId === req.body.driverId && s.status === 'active');
  if (shiftIndex > -1) shifts[shiftIndex].status = 'completed';
  reports.push(newReport);
  res.json({ success: true });
});

app.get('/api/fleet', requireAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM fleet ORDER BY "busNumber"');
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Błąd serwera' });
  }
});

// ---------------------------------------------------------
// 🔑 ZMIANA HASŁA
// ---------------------------------------------------------
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
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Błąd serwera' });
  }
});

// ---------------------------------------------------------
// 📥 CHRONIONY DOSTĘP DO PLIKÓW PDF
// ---------------------------------------------------------
app.get('/api/files/:filename', requireAuth, (req, res) => {
  const filename = req.params.filename;
  if (filename.includes('..') || filename.includes('/') || filename.includes('\\')) return res.status(400).json({ error: 'Nieprawidłowa nazwa pliku' });
  const filePath = path.join(__dirname, 'uploads', filename);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'Plik nie istnieje' });
  if (req.user.role === 'admin') return res.sendFile(filePath);
  const relativeUrl = `/api/files/${filename}`;
  const ownsShift = shifts.some(s => s.pdfUrl === relativeUrl && s.driverId === req.user.id);
  const ownsReport = reports.some(r => r.pdfUrl === relativeUrl && r.driverId === req.user.id);
  if (ownsShift || ownsReport) return res.sendFile(filePath);
  return res.status(403).json({ error: 'Brak dostępu do tego pliku' });
});

// ---------------------------------------------------------
// 🖼️ ZDJĘCIA TABLIC — PUBLICZNE
// ---------------------------------------------------------
app.get('/api/plate-images/:filename', (req, res) => {
  const filename = req.params.filename;
  if (filename.includes('..') || filename.includes('/') || filename.includes('\\')) return res.status(400).json({ error: 'Nieprawidłowa nazwa pliku' });
  const filePath = path.join(__dirname, 'uploads', 'plates', filename);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'Plik nie istnieje' });
  res.sendFile(filePath);
});

// ---------------------------------------------------------
// 🚀 ENDPOINTY CHRONIONE — TYLKO ADMIN
// ---------------------------------------------------------
app.post('/api/fleet', requireAdmin, uploadPlateImage.single('plate_image'), async (req, res) => {
  const { busNumber, brand, model, vehicleType, status, yearManufactured, assignedDriverId, assignedDriverName, notes } = req.body;
  const file = req.file;
  const id = 'bus-' + Date.now();
  const plateImageUrl = file ? `/api/plate-images/${file.filename}` : '';
  try {
    await pool.query(
      `INSERT INTO fleet (id, "busNumber", brand, model, "vehicleType", status, "yearManufactured", "assignedDriverId", "assignedDriverName", notes, "plateImageUrl")
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
      [id, busNumber || '', brand || '', model || '', vehicleType || '', status || 'eksploatowany', yearManufactured || '', assignedDriverId || '', assignedDriverName || 'Brak', notes || '', plateImageUrl]
    );
    const result = await pool.query('SELECT * FROM fleet WHERE id = $1', [id]);
    res.json({ success: true, vehicle: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Błąd serwera' });
  }
});

app.put('/api/fleet/:id', requireAdmin, uploadPlateImage.single('plate_image'), async (req, res) => {
  const { id } = req.params;
  const { busNumber, brand, model, vehicleType, status, yearManufactured, assignedDriverId, assignedDriverName, notes } = req.body;
  const file = req.file;
  try {
    const existing = await pool.query('SELECT * FROM fleet WHERE id = $1', [id]);
    if (existing.rows.length === 0) return res.status(404).json({ error: 'Nie znaleziono pojazdu' });
    const oldPlateImageUrl = existing.rows[0].plateImageUrl;
    const plateImageUrl = file ? `/api/plate-images/${file.filename}` : oldPlateImageUrl;
    await pool.query(
      `UPDATE fleet SET "busNumber"=$1, brand=$2, model=$3, "vehicleType"=$4, status=$5, "yearManufactured"=$6, "assignedDriverId"=$7, "assignedDriverName"=$8, notes=$9, "plateImageUrl"=$10 WHERE id=$11`,
      [busNumber, brand, model, vehicleType, status, yearManufactured, assignedDriverId || '', assignedDriverName || 'Brak', notes, plateImageUrl, id]
    );
    const result = await pool.query('SELECT * FROM fleet WHERE id = $1', [id]);
    res.json({ success: true, vehicle: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Błąd serwera' });
  }
});

app.delete('/api/fleet/:id', requireAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM fleet WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Błąd serwera' });
  }
});

app.post('/api/drivers', requireAdmin, async (req, res) => {
  const { login, password, displayName } = req.body;
  try {
    const existing = await pool.query('SELECT id FROM users WHERE login = $1', [login]);
    if (existing.rows.length > 0) return res.status(400).json({ success: false, message: 'Ten login jest już zajęty!' });
    const hashedPassword = await bcrypt.hash(password, 10);
    const id = 'driver-' + Date.now();
    await pool.query(
      'INSERT INTO users (id, login, password, role, "displayName") VALUES ($1,$2,$3,$4,$5)',
      [id, login, hashedPassword, 'driver', displayName]
    );
    res.json({ success: true, driver: { id, login, displayName, role: 'driver' } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Błąd serwera' });
  }
});

app.delete('/api/drivers/:id', requireAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query('SELECT id FROM users WHERE id = $1 AND role = $2', [id, 'driver']);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Nie znaleziono kierowcy' });
    await pool.query('DELETE FROM users WHERE id = $1', [id]);
    shifts = shifts.filter(s => s.driverId !== id);
    await pool.query('UPDATE fleet SET "assignedDriverId" = $1, "assignedDriverName" = $2 WHERE "assignedDriverId" = $3', ['', 'Brak', id]);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Błąd serwera' });
  }
});

app.post('/api/shifts', requireAdmin, upload.single('pdf_file'), (req, res) => {
  const data = req.body;
  const file = req.file;
  shifts = shifts.filter(s => s.driverId !== data.driverId || s.status !== 'active');
  const newShift = {
    id: Date.now(),
    driverId: data.driverId,
    driverName: data.driverName,
    line: data.line,
    brigade: data.brigade,
    bus: data.bus,
    startTime: data.startTime,
    endTime: data.endTime,
    pdfUrl: file ? `/api/files/${file.filename}` : null,
    status: 'active'
  };
  shifts.push(newShift);
  res.json({ success: true, shift: newShift });
});

app.get('/api/shifts', requireAdmin, (req, res) => {
  res.json({ shifts: shifts.filter(s => s.status === 'active') });
});

app.delete('/api/shifts/:driverId', requireAdmin, (req, res) => {
  shifts = shifts.filter(s => !(s.driverId === req.params.driverId && s.status === 'active'));
  res.json({ success: true });
});

app.get('/api/reports/pending', requireAdmin, (req, res) => {
  res.json({ reports: reports.filter(r => r.status === 'pending') });
});

app.post('/api/reports/:id/status', requireAdmin, (req, res) => {
  const reportId = parseInt(req.params.id);
  const action = req.body.action;
  const reportIndex = reports.findIndex(r => r.id === reportId);
  if (reportIndex > -1) {
    reports[reportIndex].status = action === 'approve' ? 'approved' : 'rejected';
    res.json({ success: true });
  } else {
    res.status(404).json({ error: 'Nie znaleziono raportu' });
  }
});

// ---------------------------------------------------------
// 💬 KOMUNIKATY (RAM)
// ---------------------------------------------------------
app.get('/api/messages', requireAuth, (req, res) => {
  const userId = req.user.id;
  const visible = messages.filter(m => m.isGlobal || m.toId === userId);
  const withReadFlag = visible.slice().sort((a, b) => b.id - a.id).slice(0, 50)
    .map(m => ({ ...m, isRead: messageReads.some(r => r.messageId === m.id && r.userId === userId) }));
  res.json({ messages: withReadFlag });
});

app.get('/api/messages/unread-count', requireAuth, (req, res) => {
  const userId = req.user.id;
  const visible = messages.filter(m => m.isGlobal || m.toId === userId);
  const unread = visible.filter(m => !messageReads.some(r => r.messageId === m.id && r.userId === userId));
  res.json({ count: unread.length });
});

app.post('/api/messages/:id/read', requireAuth, (req, res) => {
  const userId = req.user.id;
  const messageId = parseInt(req.params.id);
  if (!messageReads.some(r => r.messageId === messageId && r.userId === userId)) {
    messageReads.push({ messageId, userId });
  }
  res.json({ success: true });
});

app.post('/api/messages/read-all', requireAuth, (req, res) => {
  const userId = req.user.id;
  const visible = messages.filter(m => m.isGlobal || m.toId === userId);
  visible.forEach(m => {
    if (!messageReads.some(r => r.messageId === m.id && r.userId === userId)) {
      messageReads.push({ messageId: m.id, userId });
    }
  });
  res.json({ success: true });
});

app.post('/api/messages', requireAdmin, (req, res) => {
  const { toId, toName, content, isGlobal } = req.body;
  if (!content || !content.trim()) return res.status(400).json({ error: 'Treść komunikatu nie może być pusta' });
  const newMessage = {
    id: Date.now(),
    fromId: req.user.id,
    fromName: req.user.displayName,
    toId: isGlobal ? null : toId,
    toName: isGlobal ? null : toName,
    content: content.trim(),
    createdAt: new Date().toISOString(),
    isGlobal: !!isGlobal
  };
  messages.push(newMessage);
  res.json({ success: true });
});

app.delete('/api/messages/:id', requireAdmin, (req, res) => {
  const messageId = parseInt(req.params.id);
  messages = messages.filter(m => m.id !== messageId);
  messageReads = messageReads.filter(r => r.messageId !== messageId);
  res.json({ success: true });
});

app.get('/api/messages/all', requireAdmin, (req, res) => {
  const sorted = messages.slice().sort((a, b) => b.id - a.id).slice(0, 100);
  res.json({ messages: sorted });
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
// 🚀 START SERWERA
// ---------------------------------------------------------
async function startServer() {
  await initDB();

  // Stwórz admina jeśli nie istnieje
  const adminExists = await pool.query('SELECT id FROM users WHERE login = $1', ['admin']);
  if (adminExists.rows.length === 0) {
    const adminPasswordHash = await bcrypt.hash(ADMIN_PASSWORD, 10);
    await pool.query(
      'INSERT INTO users (id, login, password, role, "displayName") VALUES ($1,$2,$3,$4,$5)',
      ['admin-1', 'admin', adminPasswordHash, 'admin', 'Centrala vPKM']
    );
    console.log('✅ Konto admina utworzone');
  }

  app.listen(PORT, () => {
    console.log(`✅ Serwer uruchomiony na porcie: ${PORT}`);
    console.log(`   Dozwolone domeny CORS: ${allowedOrigins.join(', ')}`);
  });
}

startServer();