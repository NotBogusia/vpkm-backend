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
const PORT = 3001;
const SECRET = 'vpkm-tychy-super-tajny-klucz-2024-zmien-to-na-cos-swojego';

// ---------------------------------------------------------
// 🛡️ HELMET — nagłówki bezpieczeństwa
// ---------------------------------------------------------
app.use(helmet());

// ---------------------------------------------------------
// 🚦 RATE LIMITING
// ---------------------------------------------------------

// Globalne: max 100 zapytań na 15 minut z jednego IP
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Za dużo zapytań. Spróbuj ponownie za chwilę.' }
});

// Na logowanie: max 10 prób na 15 minut (anty brute-force)
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
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

const dir = './uploads';
if (!fs.existsSync(dir)) fs.mkdirSync(dir);

// ---------------------------------------------------------
// 📁 MULTER — limit rozmiaru pliku 10MB
// ---------------------------------------------------------
const storage = multer.diskStorage({
  destination: function (req, file, cb) { cb(null, 'uploads/'); },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + '-' + file.originalname);
  }
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 10 * 1024 * 1024 } // max 10MB
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

let adminPasswordHash = '';
bcrypt.hash('123', 10).then(hash => { adminPasswordHash = hash; });

let users = [];
setTimeout(() => {
  users = [
    { id: 'admin-1', login: 'admin', password: adminPasswordHash, role: 'admin', displayName: 'Centrala vPKM' }
  ];
}, 100);

let shifts = [];
let reports = [];

// ---------------------------------------------------------
// 🚀 ENDPOINTY PUBLICZNE
// ---------------------------------------------------------

app.get('/', (req, res) => {
  res.send('Serwer vPKM działa poprawnie!');
});

// Logowanie z osobnym, ostrzejszym rate limiterem
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
    pdfUrl: `/uploads/${file.filename}`,
    originalName: file.originalname,
    status: 'pending'
  };

  const shiftIndex = shifts.findIndex(s => s.driverId === req.body.driverId && s.status === 'active');
  if (shiftIndex > -1) shifts[shiftIndex].status = 'completed';

  reports.push(newReport);
  res.json({ success: true });
});

// ---------------------------------------------------------
// 🚀 ENDPOINTY CHRONIONE — TYLKO ADMIN
// ---------------------------------------------------------

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
    brigade: data.brigade,
    bus: data.bus,
    startTime: data.startTime,
    endTime: data.endTime,
    pdfUrl: file ? `/uploads/${file.filename}` : null,
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

app.listen(PORT, () => {
  console.log(`✅ Serwer uruchomiony na: http://localhost:${PORT}`);
});
