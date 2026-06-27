const express = require('express');
const cors = require('cors');
const { randomUUID } = require('crypto');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const { Pool } = require('pg');
const cloudinary = require('cloudinary').v2;
const { Readable } = require('stream');
const validator = require('validator');
const app = express();
const PORT = process.env.PORT || 3001;
const SECRET = process.env.JWT_SECRET;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const uploadToCloudinary = (buffer, folder, resourceType = 'raw') => {
  return new Promise((resolve, reject) => {
    const uploadStream = cloudinary.uploader.upload_stream(
      { folder, resource_type: resourceType },
      (error, result) => {
        if (error) reject(error);
        else resolve(result);
      }
    );
    Readable.from(buffer).pipe(uploadStream);
  });
};


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

const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Za dużo zapytań. Spróbuj ponownie za chwilę.' }
});

const uploadLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 20,
  message: { error: 'Za dużo uploadów. Poczekaj godzinę.' }
});
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5, standardHeaders: true, legacyHeaders: false, message: { error: 'Za dużo prób logowania. Poczekaj 15 minut.' } });

app.use(globalLimiter);
app.use(express.json({ limit: '1mb' }));

const dir = './uploads';
if (!fs.existsSync(dir)) fs.mkdirSync(dir);
const plateDir = './uploads/plates';
if (!fs.existsSync(plateDir)) fs.mkdirSync(plateDir, { recursive: true });

const pdfFileFilter = (req, file, cb) => {
  if (file.mimetype === 'application/pdf' && path.extname(file.originalname).toLowerCase() === '.pdf') cb(null, true);
  else cb(new Error('Tylko pliki PDF są dozwolone.'));
};

const imageFileFilter = (req, file, cb) => {
  const allowedMimes = ['image/jpeg', 'image/png', 'image/jpg'];
  const allowedExts = ['.jpg', '.jpeg', '.png'];
  if (allowedMimes.includes(file.mimetype) && allowedExts.includes(path.extname(file.originalname).toLowerCase())) cb(null, true);
  else cb(new Error('Tylko pliki JPG/PNG są dozwolone.'));
};

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: pdfFileFilter
});

const uploadPlateImage = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: imageFileFilter
});

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
      display_name TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS fleet (
      id TEXT PRIMARY KEY,
      bus_number TEXT,
      brand TEXT,
      model TEXT,
      vehicle_type TEXT,
      status TEXT DEFAULT 'eksploatowany',
      year_manufactured TEXT,
      assigned_driver_id TEXT DEFAULT '',
      assigned_driver_name TEXT DEFAULT 'Brak',
      notes TEXT DEFAULT '',
      plate_image_url TEXT DEFAULT ''
    );

    CREATE TABLE IF NOT EXISTS shifts (
      id BIGINT PRIMARY KEY,
      driver_id TEXT,
      driver_name TEXT,
      line TEXT,
      brigade TEXT,
      bus TEXT,
      start_time TEXT,
      end_time TEXT,
      pdf_url TEXT,
      status TEXT DEFAULT 'active',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS reports (
      id BIGINT PRIMARY KEY,
      driver_id TEXT,
      driver_name TEXT,
      line TEXT,
      date TEXT,
      pdf_url TEXT,
      original_name TEXT,
      status TEXT DEFAULT 'pending'
    );

    CREATE TABLE IF NOT EXISTS messages (
      id BIGINT PRIMARY KEY,
      from_id TEXT,
      from_name TEXT,
      to_id TEXT,
      to_name TEXT,
      content TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      is_global BOOLEAN DEFAULT FALSE
    );

    CREATE TABLE IF NOT EXISTS message_reads (
      message_id BIGINT,
      user_id TEXT,
      PRIMARY KEY (message_id, user_id)
    );
  `);

  await pool.query(`
    ALTER TABLE users ADD COLUMN IF NOT EXISTS employee_number TEXT DEFAULT '';
    ALTER TABLE users ADD COLUMN IF NOT EXISTS full_name TEXT DEFAULT '';
    ALTER TABLE users ADD COLUMN IF NOT EXISTS roblox_nick TEXT DEFAULT '';
    ALTER TABLE users ADD COLUMN IF NOT EXISTS position TEXT DEFAULT '';
    ALTER TABLE users ADD COLUMN IF NOT EXISTS employment_status TEXT DEFAULT 'pracujacy';
    ALTER TABLE users ADD COLUMN IF NOT EXISTS additional_info TEXT DEFAULT '';
    ALTER TABLE users ADD COLUMN IF NOT EXISTS points INTEGER DEFAULT 0;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS minuses INTEGER DEFAULT 0;
  `);

  await pool.query(`
  ALTER TABLE shifts ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW();
`);
await initSchedulesTable();

  console.log('✅ Tabele zainicjalizowane');
}

// ---------------------------------------------------------
// 🚀 PUBLICZNE
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
    const token = jwt.sign({ id: user.id, role: user.role, displayName: user.display_name }, SECRET, { expiresIn: '8h' });
    res.json({
      success: true,
      user: { id: user.id, login: user.login, role: user.role, displayName: user.display_name },
      token
    });
  } catch (err) { console.error(err); res.status(500).json({ success: false, message: 'Błąd serwera' }); }
});

// ---------------------------------------------------------
// 🚀 KIEROWCA I ADMIN
// ---------------------------------------------------------
app.get('/api/drivers', requireAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM users WHERE role = $1', ['driver']);
    res.json(result.rows.map(d => ({
      id: d.id, login: d.login, displayName: d.display_name,
      employeeNumber: d.employee_number, fullName: d.full_name,
      robloxNick: d.roblox_nick, position: d.position,
      employmentStatus: d.employment_status, additionalInfo: d.additional_info,
      points: d.points, minuses: d.minuses
    })));
  } catch (err) { console.error(err); res.status(500).json({ error: 'Błąd serwera' }); }
});

app.get('/api/drivers/me', requireAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM users WHERE id = $1', [req.user.id]);
    const d = result.rows[0];
    if (!d) return res.status(404).json({ error: 'Nie znaleziono użytkownika' });
    res.json({
      id: d.id, login: d.login, displayName: d.display_name,
      employeeNumber: d.employee_number, fullName: d.full_name,
      robloxNick: d.roblox_nick, position: d.position,
      employmentStatus: d.employment_status, additionalInfo: d.additional_info,
      points: d.points, minuses: d.minuses
    });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Błąd serwera' }); }
});

app.get('/api/shifts/:driverId', requireAuth, async (req, res) => {
  if (req.user.role === 'driver' && req.user.id !== req.params.driverId) return res.status(403).json({ error: 'Możesz sprawdzać tylko swoją służbę' });
  try {
    const result = await pool.query('SELECT * FROM shifts WHERE driver_id = $1 AND status = $2', [req.params.driverId, 'active']);
    const shift = result.rows[0];
    if (!shift) return res.json({ shift: null });
    res.json({ shift: {
      id: shift.id, driverId: shift.driver_id, driverName: shift.driver_name,
      line: shift.line, brigade: shift.brigade, bus: shift.bus,
      startTime: shift.start_time, endTime: shift.end_time,
      pdfUrl: shift.pdf_url, status: shift.status
    }});
  } catch (err) { console.error(err); res.status(500).json({ error: 'Błąd serwera' }); }
});

app.get('/api/shifts/history/:driverId', requireAuth, async (req, res) => {
  if (req.user.role === 'driver' && req.user.id !== req.params.driverId) return res.status(403).json({ error: 'Brak dostępu' });
  try {
    const result = await pool.query('SELECT * FROM shifts WHERE driver_id = $1 AND status != $2 ORDER BY created_at DESC LIMIT 20', [req.params.driverId, 'active']);
    res.json({ history: result.rows.map(s => ({
      id: s.id, driverId: s.driver_id, driverName: s.driver_name,
      line: s.line, brigade: s.brigade, bus: s.bus,
      startTime: s.start_time, endTime: s.end_time,
      pdfUrl: s.pdf_url, status: s.status
    }))});
  } catch (err) { console.error(err); res.status(500).json({ error: 'Błąd serwera' }); }
});

app.post('/api/reports', requireAuth, uploadLimiter, upload.single('report_pdf'), async (req, res) => {
  const file = req.file;
  if (!file) return res.status(400).json({ error: 'Brak pliku PDF!' });
  try {
    const result = await uploadToCloudinary(file.buffer, 'vpkm/reports', 'raw');
    const pdfUrl = result.secure_url;
    const id = Date.now();
    await pool.query(
      'INSERT INTO reports (id, driver_id, driver_name, line, date, pdf_url, original_name, status) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)',
      [id, req.body.driverId, req.body.driverName, req.body.line,
       new Date().toLocaleString('pl-PL'), pdfUrl, file.originalname, 'pending']
    );
    await pool.query('UPDATE shifts SET status = $1 WHERE driver_id = $2 AND status = $3',
      ['completed', req.body.driverId, 'active']);
    res.json({ success: true });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Błąd serwera' }); }
});

app.post('/api/fleet', requireAdmin, uploadLimiter, uploadPlateImage.single('plate_image'), async (req, res) => {
  const { busNumber, brand, model, vehicleType, status, yearManufactured, assignedDriverId, assignedDriverName, notes } = req.body;
  const file = req.file;
  const id = 'bus-' + Date.now();
  try {
    let plateImageUrl = '';
    if (file) {
      const result = await uploadToCloudinary(file.buffer, 'vpkm/plates', 'image');
      plateImageUrl = result.secure_url;
    }
    await pool.query(
      'INSERT INTO fleet (id, bus_number, brand, model, vehicle_type, status, year_manufactured, assigned_driver_id, assigned_driver_name, notes, plate_image_url) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)',
      [id, busNumber || '', brand || '', model || '', vehicleType || '', status || 'eksploatowany',
       yearManufactured || '', assignedDriverId || '', assignedDriverName || 'Brak', notes || '', plateImageUrl]
    );
    res.json({ success: true });
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
    const shiftResult = await pool.query('SELECT id FROM shifts WHERE pdf_url = $1 AND driver_id = $2', [relativeUrl, req.user.id]);
    const reportResult = await pool.query('SELECT id FROM reports WHERE pdf_url = $1 AND driver_id = $2', [relativeUrl, req.user.id]);
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
  const id = 'bus-' + randomUUID();
  const plateImageUrl = file ? `/api/plate-images/${file.filename}` : '';
  try {
    await pool.query(
      'INSERT INTO fleet (id, bus_number, brand, model, vehicle_type, status, year_manufactured, assigned_driver_id, assigned_driver_name, notes, plate_image_url) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)',
      [id, busNumber || '', brand || '', model || '', vehicleType || '', status || 'eksploatowany', yearManufactured || '', assignedDriverId || '', assignedDriverName || 'Brak', notes || '', plateImageUrl]
    );
    const result = await pool.query('SELECT * FROM fleet WHERE id = $1', [id]);
    const v = result.rows[0];
    res.json({ success: true, vehicle: {
      id: v.id, busNumber: v.bus_number, brand: v.brand, model: v.model,
      vehicleType: v.vehicle_type, status: v.status, yearManufactured: v.year_manufactured,
      assignedDriverId: v.assigned_driver_id, assignedDriverName: v.assigned_driver_name,
      notes: v.notes, plateImageUrl: v.plate_image_url
    }});
  } catch (err) { console.error(err); res.status(500).json({ error: 'Błąd serwera' }); }
});

app.put('/api/fleet/:id', requireAdmin, uploadPlateImage.single('plate_image'), async (req, res) => {
  const { id } = req.params;
  const { busNumber, brand, model, vehicleType, status, yearManufactured, assignedDriverId, assignedDriverName, notes } = req.body;
  const file = req.file;
  try {
    const existing = await pool.query('SELECT * FROM fleet WHERE id = $1', [id]);
    if (existing.rows.length === 0) return res.status(404).json({ error: 'Nie znaleziono pojazdu' });
    let plateImageUrl = existing.rows[0].plate_image_url;
    if (file) {
      const result = await uploadToCloudinary(file.buffer, 'vpkm/plates', 'image');
      plateImageUrl = result.secure_url;
    }
    await pool.query(
      'UPDATE fleet SET bus_number=$1, brand=$2, model=$3, vehicle_type=$4, status=$5, year_manufactured=$6, assigned_driver_id=$7, assigned_driver_name=$8, notes=$9, plate_image_url=$10 WHERE id=$11',
      [busNumber, brand, model, vehicleType, status, yearManufactured, assignedDriverId || '', assignedDriverName || 'Brak', notes, plateImageUrl, id]
    );
    const result2 = await pool.query('SELECT * FROM fleet WHERE id = $1', [id]);
    const v = result2.rows[0];
    res.json({ success: true, vehicle: {
      id: v.id, busNumber: v.bus_number, brand: v.brand, model: v.model,
      vehicleType: v.vehicle_type, status: v.status, yearManufactured: v.year_manufactured,
      assignedDriverId: v.assigned_driver_id, assignedDriverName: v.assigned_driver_name,
      notes: v.notes, plateImageUrl: v.plate_image_url
    }});
  } catch (err) { console.error(err); res.status(500).json({ error: 'Błąd serwera' }); }
});

app.delete('/api/fleet/:id', requireAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM fleet WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Błąd serwera' }); }
});

app.post('/api/drivers', requireAdmin, async (req, res) => {
  const { login, password, displayName, employeeNumber, fullName, robloxNick, position, employmentStatus, additionalInfo, points, minuses } = req.body;

  // Walidacja długości
  if (!login || login.length < 3 || login.length > 50) {
    return res.status(400).json({ error: 'Login musi mieć 3-50 znaków' });
  }
  if (!password || password.length < 6 || password.length > 100) {
    return res.status(400).json({ error: 'Hasło musi mieć 6-100 znaków' });
  }
  if (!displayName || displayName.length < 2 || displayName.length > 100) {
    return res.status(400).json({ error: 'Nazwa musi mieć 2-100 znaków' });
  }

  // Sanityzacja — oczyszczenie danych z niebezpiecznych znaków
  const safeLogin = validator.escape(login.trim());
  const safeDisplayName = validator.escape(displayName.trim());
  const safeFullName = fullName ? validator.escape(fullName.trim()) : '';
  const safeRobloxNick = robloxNick ? validator.escape(robloxNick.trim()) : '';
  const safePosition = position ? validator.escape(position.trim()) : '';
  const safeAdditionalInfo = additionalInfo ? validator.escape(additionalInfo.trim()) : '';
  const safeEmployeeNumber = employeeNumber ? validator.escape(employeeNumber.trim()) : '';

  try {
    const existing = await pool.query('SELECT id FROM users WHERE login = $1', [safeLogin]);
    if (existing.rows.length > 0) return res.status(400).json({ success: false, message: 'Ten login jest już zajęty!' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const id = 'driver-' + randomUUID();

    await pool.query(
      `INSERT INTO users (id, login, password, role, display_name, employee_number, full_name, roblox_nick, position, employment_status, additional_info, points, minuses)
       VALUES ($1,$2,$3,'driver',$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
      [id, safeLogin, hashedPassword, safeDisplayName, safeEmployeeNumber, safeFullName, safeRobloxNick, safePosition, employmentStatus || 'pracujacy', safeAdditionalInfo, points || 0, minuses || 0]
    );

    res.json({ success: true, driver: { id, login: safeLogin, displayName: safeDisplayName, role: 'driver' } });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Błąd serwera' }); }
});

app.put('/api/drivers/:id', requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { displayName, employeeNumber, fullName, robloxNick, position, employmentStatus, additionalInfo, points, minuses } = req.body;

  if (!displayName || displayName.length < 2 || displayName.length > 100) {
    return res.status(400).json({ error: 'Nazwa musi mieć 2-100 znaków' });
  }

  // Sanityzacja
  const safeDisplayName = validator.escape(displayName.trim());
  const safeFullName = fullName ? validator.escape(fullName.trim()) : '';
  const safeRobloxNick = robloxNick ? validator.escape(robloxNick.trim()) : '';
  const safePosition = position ? validator.escape(position.trim()) : '';
  const safeAdditionalInfo = additionalInfo ? validator.escape(additionalInfo.trim()) : '';
  const safeEmployeeNumber = employeeNumber ? validator.escape(employeeNumber.trim()) : '';

  try {
    const result = await pool.query(
      `UPDATE users SET display_name=$1, employee_number=$2, full_name=$3, roblox_nick=$4,
       position=$5, employment_status=$6, additional_info=$7, points=$8, minuses=$9
       WHERE id=$10 AND role='driver' RETURNING *`,
      [safeDisplayName, safeEmployeeNumber, safeFullName, safeRobloxNick, safePosition, employmentStatus || 'pracujacy', safeAdditionalInfo, points || 0, minuses || 0, id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Nie znaleziono kierowcy' });
    res.json({ success: true });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Błąd serwera' }); }
});

app.delete('/api/drivers/:id', requireAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query('SELECT id FROM users WHERE id = $1 AND role = $2', [id, 'driver']);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Nie znaleziono kierowcy' });
    await pool.query('DELETE FROM users WHERE id = $1', [id]);
    await pool.query('UPDATE fleet SET assigned_driver_id = $1, assigned_driver_name = $2 WHERE assigned_driver_id = $3', ['', 'Brak', id]);
    res.json({ success: true });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Błąd serwera' }); }
});

app.post('/api/shifts', requireAdmin, async (req, res) => {
  const { driverId, driverName, line, brigade, bus, startTime, endTime, scheduleFile } = req.body;
  try {
    await pool.query('UPDATE shifts SET status = $1 WHERE driver_id = $2 AND status = $3', ['cancelled', driverId, 'active']);
    const id = Date.now();
    // pdf_url teraz wskazuje na statyczny plik rozkładu (np. /weekend_2_1.pdf), nie na wgrany plik
    const pdfUrl = scheduleFile ? `/${scheduleFile}` : null;
    await pool.query(
      'INSERT INTO shifts (id, driver_id, driver_name, line, brigade, bus, start_time, end_time, pdf_url, status) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)',
      [id, driverId, driverName, line, brigade, bus, startTime, endTime, pdfUrl, 'active']
    );
    const result = await pool.query('SELECT * FROM shifts WHERE id = $1', [id]);
    const s = result.rows[0];
    res.json({ success: true, shift: {
      id: s.id, driverId: s.driver_id, driverName: s.driver_name,
      line: s.line, brigade: s.brigade, bus: s.bus,
      startTime: s.start_time, endTime: s.end_time,
      pdfUrl: s.pdf_url, status: s.status
    }});
  } catch (err) { console.error(err); res.status(500).json({ error: 'Błąd serwera' }); }
});

app.get('/api/shifts', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM shifts WHERE status = $1 ORDER BY created_at DESC', ['active']);
    res.json({ shifts: result.rows.map(s => ({
      id: s.id, driverId: s.driver_id, driverName: s.driver_name,
      line: s.line, brigade: s.brigade, bus: s.bus,
      startTime: s.start_time, endTime: s.end_time,
      pdfUrl: s.pdf_url, status: s.status
    }))});
  } catch (err) { console.error(err); res.status(500).json({ error: 'Błąd serwera' }); }
});

app.delete('/api/shifts/:driverId', requireAdmin, async (req, res) => {
  try {
    await pool.query('UPDATE shifts SET status = $1 WHERE driver_id = $2 AND status = $3', ['cancelled', req.params.driverId, 'active']);
    res.json({ success: true });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Błąd serwera' }); }
});

app.get('/api/reports/pending', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM reports WHERE status = $1 ORDER BY id DESC', ['pending']);
    res.json({ reports: result.rows.map(r => ({
      id: r.id, driverId: r.driver_id, driverName: r.driver_name,
      line: r.line, date: r.date, pdfUrl: r.pdf_url,
      originalName: r.original_name, status: r.status
    }))});
  } catch (err) { console.error(err); res.status(500).json({ error: 'Błąd serwera' }); }
});

app.post('/api/reports/:id/status', requireAdmin, async (req, res) => {
  const reportId = parseInt(req.params.id);
  const action = req.body.action;
  try {
    await pool.query('UPDATE reports SET status = $1 WHERE id = $2', [action === 'approve' ? 'approved' : 'rejected', reportId]);
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
      `SELECT m.*, EXISTS(SELECT 1 FROM message_reads r WHERE r.message_id = m.id AND r.user_id = $1) as "isRead"
       FROM messages m WHERE m.is_global = true OR m.to_id = $1 ORDER BY m.id DESC LIMIT 50`,
      [userId]
    );
    res.json({ messages: result.rows.map(m => ({
      id: m.id, fromId: m.from_id, fromName: m.from_name,
      toId: m.to_id, toName: m.to_name, content: m.content,
      createdAt: m.created_at, isGlobal: m.is_global, isRead: m.isRead
    }))});
  } catch (err) { console.error(err); res.status(500).json({ error: 'Błąd serwera' }); }
});

app.get('/api/messages/unread-count', requireAuth, async (req, res) => {
  const userId = req.user.id;
  try {
    const result = await pool.query(
      `SELECT COUNT(*) FROM messages m WHERE (m.is_global = true OR m.to_id = $1) AND NOT EXISTS(SELECT 1 FROM message_reads r WHERE r.message_id = m.id AND r.user_id = $1)`,
      [userId]
    );
    res.json({ count: parseInt(result.rows[0].count) });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Błąd serwera' }); }
});

app.post('/api/messages/:id/read', requireAuth, async (req, res) => {
  const userId = req.user.id;
  const messageId = parseInt(req.params.id);
  try {
    await pool.query('INSERT INTO message_reads (message_id, user_id) VALUES ($1,$2) ON CONFLICT DO NOTHING', [messageId, userId]);
    res.json({ success: true });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Błąd serwera' }); }
});

app.post('/api/messages/read-all', requireAuth, async (req, res) => {
  const userId = req.user.id;
  try {
    await pool.query(
      `INSERT INTO message_reads (message_id, user_id) SELECT m.id, $1 FROM messages m WHERE (m.is_global = true OR m.to_id = $1) ON CONFLICT DO NOTHING`,
      [userId]
    );
    res.json({ success: true });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Błąd serwera' }); }
});

app.post('/api/messages', requireAdmin, async (req, res) => {
  const { toId, toName, content, isGlobal } = req.body;

  if (!content || !content.trim()) {
    return res.status(400).json({ error: 'Treść komunikatu nie może być pusta' });
  }
  if (content.length > 1000) {
    return res.status(400).json({ error: 'Treść nie może przekraczać 1000 znaków' });
  }

  // Sanityzacja
  const safeContent = validator.escape(content.trim());
  const safeToName = toName ? validator.escape(toName.trim()) : '';

  try {
    const id = Date.now();
    await pool.query(
      'INSERT INTO messages (id, from_id, from_name, to_id, to_name, content, is_global) VALUES ($1,$2,$3,$4,$5,$6,$7)',
      [id, req.user.id, req.user.displayName, isGlobal ? null : toId, isGlobal ? null : safeToName, safeContent, !!isGlobal]
    );
    res.json({ success: true });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Błąd serwera' }); }
});

app.delete('/api/messages/:id', requireAdmin, async (req, res) => {
  const messageId = parseInt(req.params.id);
  try {
    await pool.query('DELETE FROM message_reads WHERE message_id = $1', [messageId]);
    await pool.query('DELETE FROM messages WHERE id = $1', [messageId]);
    res.json({ success: true });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Błąd serwera' }); }
});

app.get('/api/messages/all', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM messages ORDER BY id DESC LIMIT 100');
    res.json({ messages: result.rows.map(m => ({
      id: m.id, fromId: m.from_id, fromName: m.from_name,
      toId: m.to_id, toName: m.to_name, content: m.content,
      createdAt: m.created_at, isGlobal: m.is_global
    }))});
  } catch (err) { console.error(err); res.status(500).json({ error: 'Błąd serwera' }); }
});

// ---------------------------------------------------------
// 📅 ROZKŁADY
// ---------------------------------------------------------
async function initSchedulesTable() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS schedules (
      id BIGINT PRIMARY KEY,
      name TEXT NOT NULL,
      category TEXT NOT NULL,
      data JSONB NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
}

app.get('/api/schedules', requireAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM schedules ORDER BY created_at DESC');
    res.json(result.rows);
  } catch (err) { console.error(err); res.status(500).json({ error: 'Błąd serwera' }); }
});

app.post('/api/schedules', requireAdmin, async (req, res) => {
  const { name, category, data } = req.body;

  if (!name || name.length < 2 || name.length > 100) {
    return res.status(400).json({ error: 'Nazwa rozkładu musi mieć 2-100 znaków' });
  }
  if (!category || !['weekday', 'saturday', 'sunday'].includes(category)) {
    return res.status(400).json({ error: 'Nieprawidłowa kategoria' });
  }
  if (!data) {
    return res.status(400).json({ error: 'Brak danych rozkładu' });
  }

  // Sanityzacja nazwy
  const safeName = validator.escape(name.trim());

  try {
    const id = Date.now();
    await pool.query(
      'INSERT INTO schedules (id, name, category, data) VALUES ($1,$2,$3,$4)',
      [id, safeName, category, JSON.stringify(data)]
    );
    res.json({ success: true, id });
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
  try {
    await initDB();
  } catch (err) {
    console.error('❌ Błąd inicjalizacji bazy danych:', err);
    process.exit(1);
  }

  try {
    const adminExists = await pool.query('SELECT id FROM users WHERE login = $1', ['admin']);
    if (adminExists.rows.length === 0) {
      const adminPasswordHash = await bcrypt.hash(ADMIN_PASSWORD, 10);
      await pool.query(
        'INSERT INTO users (id, login, password, role, display_name) VALUES ($1,$2,$3,$4,$5)',
        ['admin-1', 'admin', adminPasswordHash, 'admin', 'Centrala vPKM']
      );
      console.log('✅ Konto admina utworzone');
    }
  } catch (err) {
    console.error('❌ Błąd tworzenia admina:', err);
    process.exit(1);
  }

  app.listen(PORT, () => {
    console.log(`✅ Serwer uruchomiony na porcie: ${PORT}`);
    console.log(`   Dozwolone domeny CORS: ${allowedOrigins.join(', ')}`);
  });
}

startServer();