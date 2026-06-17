const express = require('express');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

// Inicjalizacja aplikacji
const app = express();
const PORT = 3001; // Serwer będzie działał na porcie 3001

// Odblokowanie komunikacji między Reactem (port 3000) a Node (port 3001)
app.use(cors());
// Pozwala serwerowi czytać dane tekstowe w formacie JSON
app.use(express.json()); 
// Udostępnia folder "uploads" publicznie, żeby admin mógł pobierać z niego PDF-y
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// ---------------------------------------------------------
// 📁 KONFIGURACJA ZAPISU PLIKÓW (MULTER)
// ---------------------------------------------------------
// Tworzymy foldery, jeśli nie istnieją
const dir = './uploads';
if (!fs.existsSync(dir)) fs.mkdirSync(dir);

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    // Wszystkie pliki lądują w folderze "uploads"
    cb(null, 'uploads/');
  },
  filename: function (req, file, cb) {
    // Zmieniamy nazwę pliku, żeby była unikalna (dodajemy aktualną datę)
    // Zabezpiecza to przed nadpisaniem pliku o tej samej nazwie
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + '-' + file.originalname);
  }
});
const upload = multer({ storage: storage });

// ---------------------------------------------------------
// 🗄️ BAZA DANYCH (TYMCZASOWA)
// Na etapie testów trzymamy dane w pamięci RAM serwera (w tablicach).
// Później zmienisz to na MongoDB lub PostgreSQL.
// ---------------------------------------------------------
let shifts = []; // Wystawione służby przez admina
let reports = []; // Raporty wysłane przez kierowców po jeździe

// ---------------------------------------------------------
// 🚀 ENDPOINTY (Trasy, z którymi łączy się React)
// ---------------------------------------------------------

// 1. Sprawdzanie, czy serwer żyje
app.get('/', (req, res) => {
  res.send('Serwer vPKM działa poprawnie!');
});

// 2. ADMIN: Wystawianie nowej służby (odbiera plik z rozkładem)
// 'pdf_file' to nazwa pola z plikiem z naszego formularza
app.post('/api/shifts', upload.single('pdf_file'), (req, res) => {
  const data = req.body; // Tekst z formularza (Linia, Brygada, itp.)
  const file = req.file; // Załączony plik PDF

  const newShift = {
    id: Date.now(),
    driver: data.driver,
    line: data.line,
    brigade: data.brigade,
    bus: data.bus,
    startTime: data.startTime,
    endTime: data.endTime,
    pdfUrl: file ? `/uploads/${file.filename}` : null,
    status: 'active'
  };

  shifts.push(newShift); // Zapisujemy w naszej tymczasowej bazie
  console.log('Nowa służba dodana:', newShift);
  
  res.json({ message: 'Służba wystawiona pomyślnie!', shift: newShift });
});

// 3. KIEROWCA: Pobieranie swojej służby
app.get('/api/shifts/:driverName', (req, res) => {
  const driverName = req.params.driverName;
  // Szukamy w bazie aktywnej służby dla tego kierowcy
  const myShift = shifts.find(s => s.driver === driverName && s.status === 'active');
  
  if (myShift) {
    res.json({ shift: myShift });
  } else {
    res.json({ shift: null, message: 'Brak przypisanych służb.' });
  }
});

// 4. KIEROWCA: Wysyłanie raportu po służbie (odbiera PDF)
app.post('/api/reports', upload.single('report_pdf'), (req, res) => {
  const file = req.file;
  
  if (!file) {
    return res.status(400).json({ error: 'Brak pliku PDF!' });
  }

  const newReport = {
    id: Date.now(),
    driver: req.body.driver,
    line: req.body.line,
    date: new Date().toLocaleString('pl-PL'),
    pdfUrl: `/uploads/${file.filename}`, // Link do pobrania pliku
    originalName: file.originalname,
    status: 'pending' // 'pending' = czeka na sprawdzenie przez admina
  };

  reports.push(newReport);
  console.log('Nowy raport otrzymany:', newReport);

  res.json({ message: 'Raport dostarczony do dyspozytorni!' });
});

// 5. ADMIN: Pobieranie listy raportów do sprawdzenia
app.get('/api/reports/pending', (req, res) => {
  const pendingReports = reports.filter(r => r.status === 'pending');
  res.json({ reports: pendingReports });
});

// 6. ADMIN: Zmiana statusu raportu (Zatwierdź / Odrzuć)
app.post('/api/reports/:id/status', (req, res) => {
  const reportId = parseInt(req.params.id);
  const action = req.body.action; // np. 'approve' lub 'reject'

  const reportIndex = reports.findIndex(r => r.id === reportId);
  
  if (reportIndex > -1) {
    reports[reportIndex].status = action === 'approve' ? 'approved' : 'rejected';
    res.json({ message: `Status zmieniony na: ${action}` });
  } else {
    res.status(404).json({ error: 'Nie znaleziono raportu' });
  }
});

// ---------------------------------------------------------
// 🏁 URUCHOMIENIE SERWERA
// ---------------------------------------------------------
app.listen(PORT, () => {
  console.log(`=================================`);
  console.log(`✅ Serwer uruchomiony!`);
  console.log(`✅ Nasłuchuję na: http://localhost:${PORT}`);
  console.log(`=================================`);
});