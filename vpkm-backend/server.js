const express = require('express');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = 3001;

app.use(cors());
app.use(express.json()); 
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

const dir = './uploads';
if (!fs.existsSync(dir)) fs.mkdirSync(dir);

const storage = multer.diskStorage({
  destination: function (req, file, cb) { cb(null, 'uploads/'); },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + '-' + file.originalname);
  }
});
const upload = multer({ storage: storage });

let users = [
  { id: 'admin-1', login: 'admin', password: '123', role: 'admin', displayName: 'Centrala vPKM' }
]; 
let shifts = []; 
let reports = []; 

app.post('/api/login', (req, res) => {
  const { login, password } = req.body;
  const user = users.find(u => u.login === login && u.password === password);
  if (user) {
    const { password, ...safeUser } = user;
    res.json({ success: true, user: safeUser });
  } else {
    res.status(401).json({ success: false, message: 'Błędny login lub hasło!' });
  }
});

app.post('/api/drivers', (req, res) => {
  const { login, password, displayName } = req.body;
  if (users.some(u => u.login === login)) {
    return res.status(400).json({ success: false, message: 'Ten login jest już zajęty!' });
  }
  const newDriver = {
    id: 'driver-' + Date.now(),
    login, password, role: 'driver', displayName
  };
  users.push(newDriver);
  res.json({ success: true, driver: newDriver });
});

app.get('/api/drivers', (req, res) => {
  const drivers = users
    .filter(u => u.role === 'driver')
    .map(d => ({ id: d.id, displayName: d.displayName, login: d.login }));
  res.json(drivers);
});

app.post('/api/shifts', upload.single('pdf_file'), (req, res) => {
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

// Admin: Lista wszystkich aktywnych służb
app.get('/api/shifts', (req, res) => {
  res.json({ shifts: shifts.filter(s => s.status === 'active') });
});

app.get('/api/shifts/:driverId', (req, res) => {
  const driverId = req.params.driverId;
  const myShift = shifts.find(s => s.driverId === driverId && s.status === 'active');
  if (myShift) {
    res.json({ shift: myShift });
  } else {
    res.json({ shift: null });
  }
});

// Admin: Anulowanie służby
app.delete('/api/shifts/:driverId', (req, res) => {
  const driverId = req.params.driverId;
  shifts = shifts.filter(s => s.driverId !== driverId);
  res.json({ success: true });
});

app.post('/api/reports', upload.single('report_pdf'), (req, res) => {
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

app.get('/api/reports/pending', (req, res) => {
  res.json({ reports: reports.filter(r => r.status === 'pending') });
});

app.post('/api/reports/:id/status', (req, res) => {
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