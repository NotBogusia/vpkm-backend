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
// 🔑 SEKRETY Z ZMIENNYCH ŚRODOWISKOWYCH
// ---------------------------------------------------------
const SECRET = process.env.JWT_SECRET;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

if (!SECRET) {
  console.error('❌ BŁĄD KRYTYCZNY: zmienna środowiskowa JWT_SECRET nie jest ustawiona.');
  process.exit(1);
}
if (!ADMIN_PASSWORD) {
  console.error('❌ BŁĄD KRYTYCZNY: zmienna środowiskowa ADMIN_PASSWORD nie jest ustawiona.');
  process.exit(1);
}

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
const globalLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 1000, standardHeaders: true, legacyHeaders: false, message: { error: 'Za dużo zapytań. Spróbuj ponownie za chwilę.' } });
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100, standardHeaders: true, legacyHeaders: false, message: { error: 'Za dużo prób logowania. Poczekaj 15 minut.' } });

app.use(globalLimiter);
app.use(express.json());

const dir = './uploads';
if (!fs.existsSync(dir)) fs.mkdirSync(dir);

const plateDir = './uploads/plates';
if (!fs.existsSync(plateDir)) fs.mkdirSync(plateDir, { recursive: true });

// ---------------------------------------------------------
// 📁 MULTER — PDF (raporty, rozkłady służb)
// ---------------------------------------------------------
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
  if (isPdfMime && isPdfExt) { cb(null, true); }
  else { cb(new Error('Tylko pliki PDF są dozwolone.')); }
};

const upload = multer({ storage: storage, limits: { fileSize: 10 * 1024 * 1024 }, fileFilter: pdfFileFilter });

// ---------------------------------------------------------
// 📁 MULTER — zdjęcia tablic rejestracyjnych (JPG/PNG)
// ---------------------------------------------------------
const plateStorage = multer.diskStorage({
  destination: function (req, file, cb) { cb(null, 'uploads/plates/'); },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const safeName = file.originalname.replace(/[^a-zA-Z0-9.\-_]/g, '_');
    cb(null, uniqueSuffix + '-' + safeName);
  }
});

const imageFileFilter = (req, file, cb) => {
  const allowedMimes = ['image/jpeg', 'image/png', 'image/jpg'];
  const allowedExts = ['.jpg', '.jpeg', '.png'];
  const isImageMime = allowedMimes.includes(file.mimetype);
  const isImageExt = allowedExts.includes(path.extname(file.originalname).toLowerCase());
  if (isImageMime && isImageExt) { cb(null, true); }
  else { cb(new Error('Tylko pliki JPG/PNG są dozwolone.')); }
};

const uploadPlateImage = multer({ storage: plateStorage, limits: { fileSize: 5 * 1024 * 1024 }, fileFilter: imageFileFilter });

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
let users = [];
let shifts = [];
let reports = [];

// 🆕 fleet z nowymi polami: vehicleType (skrót), status, plateImageUrl
// (registrationNumber i fleetType — USUNIĘTE na życzenie)
let fleet = [
  { id: 'bus-1', busNumber: '421', brand: 'Solaris', model: 'Urbino 18', vehicleType: 'CN', status: 'eksploatowany', yearManufactured: '2019', assignedDriverId: '', assignedDriverName: 'Brak', notes: '', plateImageUrl: '' },
  { id: 'bus-2', busNumber: '105', brand: 'MAN', model: "Lion's City", vehicleType: 'BN', status: 'eksploatowany', yearManufactured: '2017', assignedDriverId: '', assignedDriverName: 'Brak', notes: '', plateImageUrl: '' }
];

// ---------------------------------------------------------
// 🚀 ENDPOINTY PUBLICZNE
// ---------------------------------------------------------
app.get('/', (req, res) => { res.send('Serwer vPKM działa poprawnie!'); });

app.post('/api/login', loginLimiter, async (req, res) => {
  const { login, password } = req.body;
  const user = users.find(u => u.login === login);
  if (!user) return res.status(401).json({ success: false, message: 'Błędny login lub hasło!' });
  const passwordMatch = await bcrypt.compare(password, user.password);
  if (!passwordMatch) return res.status(401).json({ success: false, message: 'Błędny login lub hasło!' });
  const token = jwt.sign({ id: user.id, role: user.role, displayName: user.displayName }, SECRET, { expiresIn: '8h' });
  const { password: _, ...safeUser } = user;
  res.json({ success: true, user: safeUser, token });
});

// ---------------------------------------------------------
// 🚀 ENDPOINTY CHRONIONE — KIEROWCA I ADMIN
// ---------------------------------------------------------
app.get('/api/drivers', requireAuth, (req, res) => {
  const drivers = users.filter(u => u.role === 'driver').map(d => ({ id: d.id, displayName: d.displayName, login: d.login }));
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

app.get('/api/fleet', requireAuth, (req, res) => {
  res.json(fleet);
});

// ---------------------------------------------------------
// 🔑 ZMIANA HASŁA (własnego)
// ---------------------------------------------------------
app.post('/api/change-password', requireAuth, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!newPassword || newPassword.length < 6) {
    return res.status(400).json({ error: 'Nowe hasło musi mieć minimum 6 znaków' });
  }
  const user = users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'Nie znaleziono użytkownika' });
  const passwordMatch = await bcrypt.compare(currentPassword, user.password);
  if (!passwordMatch) return res.status(401).json({ error: 'Obecne hasło jest nieprawidłowe' });
  user.password = await bcrypt.hash(newPassword, 10);
  res.json({ success: true });
});

// ---------------------------------------------------------
// 📥 CHRONIONY DOSTĘP DO PLIKÓW PDF
// ---------------------------------------------------------
app.get('/api/files/:filename', requireAuth, (req, res) => {
  const filename = req.params.filename;
  if (filename.includes('..') || filename.includes('/') || filename.includes('\\')) {
    return res.status(400).json({ error: 'Nieprawidłowa nazwa pliku' });
  }
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
// 🖼️ DOSTĘP DO ZDJĘĆ TABLIC REJESTRACYJNYCH
// ---------------------------------------------------------
// Zdjęcia tablic są widoczne dla każdego zalogowanego (kierowca i admin
// mają wgląd w tabor), więc requireAuth jest wystarczające — bez
// dodatkowej weryfikacji właściciela jak przy plikach PDF.
app.get('/api/plate-images/:filename', (req, res) => {
  const filename = req.params.filename;
  if (filename.includes('..') || filename.includes('/') || filename.includes('\\')) {
    return res.status(400).json({ error: 'Nieprawidłowa nazwa pliku' });
  }
  const filePath = path.join(__dirname, 'uploads', 'plates', filename);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'Plik nie istnieje' });
  res.sendFile(filePath);
});

// ---------------------------------------------------------
// 🚀 ENDPOINTY CHRONIONE — TYLKO ADMIN
// ---------------------------------------------------------

// 🆕 Dodawanie pojazdu — teraz przyjmuje multipart/form-data
// (bo formularz wysyła też plik plate_image)
app.post('/api/fleet', requireAdmin, uploadPlateImage.single('plate_image'), (req, res) => {
  const { busNumber, brand, model, vehicleType, status, yearManufactured, assignedDriverId, assignedDriverName, notes } = req.body;
  const file = req.file;

  const newVehicle = {
    id: 'bus-' + Date.now(),
    busNumber: busNumber || '',
    brand: brand || '',
    model: model || '',
    vehicleType: vehicleType || '',
    status: status || 'eksploatowany',
    yearManufactured: yearManufactured || '',
    assignedDriverId: assignedDriverId || '',
    assignedDriverName: assignedDriverName || 'Brak',
    notes: notes || '',
    plateImageUrl: file ? `/api/plate-images/${file.filename}` : ''
  };

  fleet.push(newVehicle);
  res.json({ success: true, vehicle: newVehicle });
});

// 🆕 Edycja pojazdu — też multipart/form-data, zachowuje stare zdjęcie
// jeśli nowe nie zostało przesłane.
app.put('/api/fleet/:id', requireAdmin, uploadPlateImage.single('plate_image'), (req, res) => {
  const id = req.params.id;
  const { busNumber, brand, model, vehicleType, status, yearManufactured, assignedDriverId, assignedDriverName, notes } = req.body;
  const file = req.file;
  const index = fleet.findIndex(b => b.id === id);

  if (index > -1) {
    const oldPlateImageUrl = fleet[index].plateImageUrl;
    fleet[index] = {
      ...fleet[index],
      busNumber: busNumber ?? fleet[index].busNumber,
      brand: brand ?? fleet[index].brand,
      model: model ?? fleet[index].model,
      vehicleType: vehicleType ?? fleet[index].vehicleType,
      status: status || fleet[index].status,
      yearManufactured: yearManufactured ?? fleet[index].yearManufactured,
      assignedDriverId: assignedDriverId || '',
      assignedDriverName: assignedDriverName || 'Brak',
      notes: notes ?? fleet[index].notes,
      plateImageUrl: file ? `/api/plate-images/${file.filename}` : oldPlateImageUrl
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
  const newDriver = { id: 'driver-' + Date.now(), login, password: hashedPassword, role: 'driver', displayName };
  users.push(newDriver);
  const { password: _, ...safeDriver } = newDriver;
  res.json({ success: true, driver: safeDriver });
});

app.delete('/api/drivers/:id', requireAdmin, (req, res) => {
  const id = req.params.id;
  const index = users.findIndex(u => u.id === id && u.role === 'driver');
  if (index === -1) return res.status(404).json({ error: 'Nie znaleziono kierowcy' });
  users.splice(index, 1);
  shifts = shifts.filter(s => s.driverId !== id);
  fleet.forEach(v => { if (v.assignedDriverId === id) { v.assignedDriverId = ''; v.assignedDriverName = 'Brak'; } });
  res.json({ success: true });
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
// 💬 KOMUNIKATY (w RAM)
// ---------------------------------------------------------
let messages = [];
let messageReads = []; // { messageId, userId }

app.get('/api/messages', requireAuth, (req, res) => {
  const userId = req.user.id;
  const visible = messages.filter(m => m.isGlobal || m.toId === userId);
  const withReadFlag = visible
    .slice()
    .sort((a, b) => b.id - a.id)
    .slice(0, 50)
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
// ⚠️ CENTRALNY HANDLER BŁĘDÓW
// ---------------------------------------------------------
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    return res.status(400).json({ error: 'Błąd przesyłania pliku: ' + err.message });
  }
  if (err && (err.message === 'Tylko pliki PDF są dozwolone.' || err.message === 'Tylko pliki JPG/PNG są dozwolone.')) {
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
  const adminPasswordHash = await bcrypt.hash(ADMIN_PASSWORD, 10);
  users.push({ id: 'admin-1', login: 'admin', password: adminPasswordHash, role: 'admin', displayName: 'Centrala vPKM' });

  app.listen(PORT, () => {
    console.log(`✅ Serwer uruchomiony na porcie: ${PORT}`);
    console.log(`   Dozwolone domeny CORS: ${allowedOrigins.join(', ')}`);
  });
}

startServer();