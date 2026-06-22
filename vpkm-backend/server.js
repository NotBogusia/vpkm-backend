const express = require('express');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');

const app = express();
const PORT = process.env.PORT || 3001;

// ---------------------------------------------------------
// 🔑 SEKRETY Z ZMIENNYCH ŚRODOWISKOWYCH (PUNKT 1 i 2)
// ---------------------------------------------------------
// Serwer NIE WYSTARTUJE bez tych zmiennych ustawionych w Railway.
// To wymusza, że nikt nie zostawi domyślnego/hardcodowanego sekretu.
const SECRET = process.env.JWT_SECRET;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

if (!SECRET) {
  console.error('❌ BŁĄD KRYTYCZNY: zmienna środowiskowa JWT_SECRET nie jest ustawiona.');
  console.error('   Ustaw ją w Railway (Settings → Variables) i zrestartuj serwis.');
  process.exit(1);
}

if (!ADMIN_PASSWORD) {
  console.error('❌ BŁĄD KRYTYCZNY: zmienna środowiskowa ADMIN_PASSWORD nie jest ustawiona.');
  console.error('   Ustaw ją w Railway (Settings → Variables) i zrestartuj serwis.');
  process.exit(1);
}

// ---------------------------------------------------------
// 🛡️ HELMET — nagłówki bezpieczeństwa
// ---------------------------------------------------------
app.use(helmet());

// Railway stawia aplikację za reverse proxy — bez tego express-rate-limit
// liczy limity względem adresu IP proxy, a nie prawdziwego klienta.
app.set('trust proxy', 1);

// ---------------------------------------------------------
// 🌐 CORS — TYLKO DOZWOLONE DOMENY (PUNKT 5)
// ---------------------------------------------------------
// FRONTEND_URL w Railway np.:
// FRONTEND_URL=https://twoja-domena.vercel.app,https://twoj-projekt.vercel.app
const allowedOrigins = (process.env.FRONTEND_URL || 'http://localhost:5173')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

app.use(cors({
  origin: function (origin, callback) {
    // brak origin = zapytania serwer-serwer / curl / Postman — przepuszczamy
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

// ---------------------------------------------------------
// STANDARDOWE MIDDLEWARE
// ---------------------------------------------------------
app.use(express.json());

const dir = './uploads';
if (!fs.existsSync(dir)) fs.mkdirSync(dir);

// ⚠️ UWAGA: usunięto `app.use('/uploads', express.static(...))`.
// Pliki nie są już publicznie dostępne — patrz endpoint /api/files/:filename
// chroniony przez requireAuth niżej (PUNKT 4).

// ---------------------------------------------------------
// 📁 MULTER — limit rozmiaru pliku 10MB + WALIDACJA TYPU (PUNKT 3)
// ---------------------------------------------------------
const storage = multer.diskStorage({
  destination: function (req, file, cb) { cb(null, 'uploads/'); },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    // Sanityzacja oryginalnej nazwy pliku — usuwamy wszystko poza
    // literami, cyframi, myślnikiem, podkreślnikiem i kropką.
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
  limits: { fileSize: 10 * 1024 * 1024 }, // max 10MB
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
// 🗄️ BAZA DANYCH (W RAM)
// ---------------------------------------------------------
// ⚠️ PRZYPOMNIENIE: to wciąż dane w pamięci procesu — znikają przy każdym
// restarcie/deployu. To temat na kolejny krok (migracja na Postgres),
// nieobjęty tym patchem (punkty 1-5).

let users = [];
let shifts = [];
let reports = [];

let fleet = [
  { id: 'bus-1', busNumber: '421', model: 'Solaris Urbino 18', assignedDriverId: '', assignedDriverName: 'Brak' },
  { id: 'bus-2', busNumber: '105', model: 'MAN Lion\'s City', assignedDriverId: '', assignedDriverName: 'Brak' }
];

// ---------------------------------------------------------
// 🚀 ENDPOINTY PUBLICZNE
// ---------------------------------------------------------

app.get('/', (req, res) => {
  res.send('Serwer vPKM działa poprawnie!');
});

app.post('/api/login', loginLimiter, async (req, res) => {
  const { login, password } = req.body;
  const user = users.find(u => u.login === login);

  if (!user) {
    return res.status(401).json({ success: false, message: 'Błędny login lub hasło!' });
  }

  const passwordMatch = await bcrypt.compare(password, user.password);
  if (!passwordMatch) {
    return res.status(401).json({ success: false, message: 'Błędny login lub hasło!' });
  }

  const token = jwt.sign(
    { id: user.id, role: user.role, displayName: user.displayName },
    SECRET,
    { expiresIn: '8h' }
  );

  const { password: _, ...safeUser } = user;
  res.json({ success: true, user: safeUser, token });
});

// ---------------------------------------------------------
// 🚀 ENDPOINTY CHRONIONE — KIEROWCA I ADMIN
// ---------------------------------------------------------

app.get('/api/drivers', requireAuth, (req, res) => {
  const drivers = users
    .filter(u => u.role === 'driver')
    .map(d => ({ id: d.id, displayName: d.displayName, login: d.login }));
  res.json(drivers);
});

app.get('/api/shifts/:driverId', requireAuth, (req, res) => {
  if (req.user.role === 'driver' && req.user.id !== req.params.driverId) {
    return res.status(403).json({ error: 'Możesz sprawdzać tylko swoją służbę' });
  }
  const driverId = req.params.driverId;
  const myShift = shifts.find(s => s.driverId === driverId && s.status === 'active');
  res.json({ shift: myShift || null });
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

app.get('/api/fleet', requireAuth, (req, res) => {
  res.json(fleet);
});

// ---------------------------------------------------------
// 📥 PUNKT 4: CHRONIONY DOSTĘP DO PLIKÓW
// ---------------------------------------------------------
// Zastępuje publiczny katalog statyczny /uploads. Każde pobranie pliku
// wymaga prawidłowego tokenu. Admin widzi wszystko, kierowca tylko pliki
// powiązane z jego własną służbą lub jego własnym raportem.

app.get('/api/files/:filename', requireAuth, (req, res) => {
  const filename = req.params.filename;

  // Ochrona przed path traversal (np. ../../etc/passwd)
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
  const ownsShift = shifts.some(s => s.pdfUrl === relativeUrl && s.driverId === req.user.id);
  const ownsReport = reports.some(r => r.pdfUrl === relativeUrl && r.driverId === req.user.id);

  if (ownsShift || ownsReport) {
    return res.sendFile(filePath);
  }

  return res.status(403).json({ error: 'Brak dostępu do tego pliku' });
});

// ---------------------------------------------------------
// 🚀 ENDPOINTY CHRONIONE — TYLKO ADMIN
// ---------------------------------------------------------

app.post('/api/fleet', requireAdmin, (req, res) => {
  const { busNumber, model, assignedDriverId, assignedDriverName } = req.body;

  const newVehicle = {
    id: 'bus-' + Date.now(),
    busNumber,
    model,
    assignedDriverId: assignedDriverId || '',
    assignedDriverName: assignedDriverName || 'Brak'
  };

  fleet.push(newVehicle);
  res.json({ success: true, vehicle: newVehicle });
});

app.put('/api/fleet/:id', requireAdmin, (req, res) => {
  const id = req.params.id;
  const { busNumber, model, assignedDriverId, assignedDriverName } = req.body;
  const index = fleet.findIndex(b => b.id === id);

  if (index > -1) {
    fleet[index] = {
      ...fleet[index],
      busNumber,
      model,
      assignedDriverId: assignedDriverId || '',
      assignedDriverName: assignedDriverName || 'Brak'
    };
    res.json({ success: true, vehicle: fleet[index] });
  } else {
    res.status(404).json({ error: 'Nie znaleziono takiego pojazdu w bazie taboru!' });
  }
});

app.delete('/api/fleet/:id', requireAdmin, (req, res) => {
  const id = req.params.id;
  fleet = fleet.filter(b => b.id !== id);
  res.json({ success: true });
});

app.post('/api/drivers', requireAdmin, async (req, res) => {
  const { login, password, displayName } = req.body;

  if (users.some(u => u.login === login)) {
    return res.status(400).json({ success: false, message: 'Ten login jest już zajęty!' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  const newDriver = {
    id: 'driver-' + Date.now(),
    login,
    password: hashedPassword,
    role: 'driver',
    displayName
  };

  users.push(newDriver);
  const { password: _, ...safeDriver } = newDriver;
  res.json({ success: true, driver: safeDriver });
});

app.post('/api/shifts', requireAdmin, upload.single('pdf_file'), (req, res) => {
  const data = req.body;
  const file = req.file;

  shifts = shifts.filter(s => s.driverId !== data.driverId);

  const newShift = {
    id: Date.now(),
    driverId: data.driverId,
    driverName: data.driverName,
    line: data.line,
    get brigade() { return data.brigade; },
    set brigade(value) { data.brigade = value; },
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
  shifts = shifts.filter(s => s.driverId !== req.params.driverId);
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
// ⚠️ CENTRALNY HANDLER BŁĘDÓW (multer / CORS / inne)
// ---------------------------------------------------------
// Musi być zarejestrowany jako ostatni middleware.
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
// Hasło admina jest teraz zahaszowane PRZED startem serwera (nie w setTimeout
// po starcie), więc nie ma już krótkiego okna, w którym logowanie nie działa.
async function startServer() {
  const adminPasswordHash = await bcrypt.hash(ADMIN_PASSWORD, 10);
  users.push({
    id: 'admin-1',
    login: 'admin',
    password: adminPasswordHash,
    role: 'admin',
    displayName: 'Centrala vPKM'
  });

  app.listen(PORT, () => {
    console.log(`✅ Serwer uruchomiony na porcie: ${PORT}`);
    console.log(`   Dozwolone domeny CORS: ${allowedOrigins.join(', ')}`);
  });
}

startServer();