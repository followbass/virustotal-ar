const express = require('express');
const multer = require('multer');
const fetch = require('node-fetch');
const cors = require('cors');
const fs = require('fs');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;
const upload = multer({ dest: 'uploads/' });
const API_KEY = process.env.VIRUSTOTAL_API_KEY;

app.use(cors()); // السماح بالطلبات من أي نطاق
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// فحص رابط
app.post('/scan-url', async (req, res) => {
  const { url } = req.body;

  try {
    const scanRes = await fetch('https://www.virustotal.com/api/v3/urls', {
      method: 'POST',
      headers: {
        'x-apikey': API_KEY,
        'content-type': 'application/x-www-form-urlencoded'
      },
      body: `url=${encodeURIComponent(url)}`
    });

    const scanData = await scanRes.json();
    const analysisId = scanData.data.id;

    const reportRes = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
      headers: { 'x-apikey': API_KEY }
    });

    const reportData = await reportRes.json();
    res.json(reportData);
  } catch (error) {
    res.status(500).json({ error: 'خطأ أثناء فحص الرابط' });
  }
});

// فحص ملف
app.post('/scan-file', upload.single('file'), async (req, res) => {
  try {
    const fileStream = fs.createReadStream(req.file.path);

    const scanRes = await fetch('https://www.virustotal.com/api/v3/files', {
      method: 'POST',
      headers: {
        'x-apikey': API_KEY
      },
      body: fileStream
    });

    const scanData = await scanRes.json();
    const analysisId = scanData.data.id;

    const reportRes = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
      headers: { 'x-apikey': API_KEY }
    });

    const reportData = await reportRes.json();
    fs.unlinkSync(req.file.path); // حذف الملف بعد الفحص

    res.json(reportData);
  } catch (error) {
    res.status(500).json({ error: 'خطأ أثناء فحص الملف' });
  }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
