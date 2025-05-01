const express = require('express');
const multer = require('multer');
const cors = require('cors');
const fs = require('fs');
const fetch = require('node-fetch');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 10000;
const apiKey = process.env.VIRUSTOTAL_API_KEY;

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const upload = multer({ dest: 'uploads/' });

app.post('/scan-url', async (req, res) => {
  const { url } = req.body;
  try {
    const submitResponse = await fetch('https://www.virustotal.com/api/v3/urls', {
      method: 'POST',
      headers: {
        'x-apikey': apiKey,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: `url=${encodeURIComponent(url)}`
    });

    const submitData = await submitResponse.json();
    const id = submitData.data?.id;
    if (!id) return res.json({ error: "فشل إرسال الرابط للتحليل." });

    await new Promise(resolve => setTimeout(resolve, 4000));

    const resultResponse = await fetch(`https://www.virustotal.com/api/v3/analyses/${id}`, {
      headers: { 'x-apikey': apiKey }
    });

    const resultData = await resultResponse.json();
    const stats = resultData.data?.attributes?.stats;

    if (!stats) return res.json({ error: "فشل الحصول على نتيجة الفحص." });

    const harmful = stats.malicious + stats.suspicious > 0;
    const engines = resultData.data.attributes.results || {};

    const التفاصيل = Object.entries(engines)
      .filter(([_, val]) => val.result)
      .slice(0, 6)
      .map(([محرك, val]) => ({
        المحرك,
        النتيجة: val.result
      }));

    res.json({
      النتيجة: harmful ? 'ضار' : 'نظيف',
      التفاصيل: التفاصيل.length > 0 ? التفاصيل : 'لم يتم الكشف عن تهديدات.'
    });

  } catch (e) {
    console.error("URL Error:", e);
    res.json({ error: "حدث خطأ أثناء فحص الرابط." });
  }
});

app.post('/scan-file', upload.single('file'), async (req, res) => {
  try {
    const file = req.file;
    const fileStream = fs.createReadStream(file.path);

    const uploadResponse = await fetch('https://www.virustotal.com/api/v3/files', {
      method: 'POST',
      headers: {
        'x-apikey': apiKey
      },
      body: fileStream
    });

    const uploadData = await uploadResponse.json();
    const id = uploadData.data?.id;
    if (!id) return res.json({ error: "فشل رفع الملف للتحليل." });

    await new Promise(resolve => setTimeout(resolve, 4000));

    const resultResponse = await fetch(`https://www.virustotal.com/api/v3/analyses/${id}`, {
      headers: { 'x-apikey': apiKey }
    });

    const resultData = await resultResponse.json();
    const stats = resultData.data?.attributes?.stats;

    if (!stats) return res.json({ error: "فشل الحصول على نتيجة الفحص." });

    const harmful = stats.malicious + stats.suspicious > 0;
    const engines = resultData.data.attributes.results || {};

    const التفاصيل = Object.entries(engines)
      .filter(([_, val]) => val.result)
      .slice(0, 6)
      .map(([محرك, val]) => ({
        المحرك,
        النتيجة: val.result
      }));

    res.json({
      النتيجة: harmful ? 'ضار' : 'نظيف',
      التفاصيل: التفاصيل.length > 0 ? التفاصيل : 'لم يتم الكشف عن تهديدات.'
    });

  } catch (e) {
    console.error("File Error:", e);
    res.json({ error: "حدث خطأ أثناء فحص الملف." });
  }
});

app.get('/', (req, res) => {
  res.send('خدمة فحص الروابط والملفات تعمل بنجاح.');
});

app.listen(port, () => {
  console.log(`الخادم يعمل على المنفذ ${port}`);
});
