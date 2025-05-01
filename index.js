const express = require('express');
const multer = require('multer');
const cors = require('cors');
const fs = require('fs');
const fetch = require('node-fetch');
const FormData = require('form-data');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 10000;
const apiKey = process.env.VIRUSTOTAL_API_KEY;

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const upload = multer({ dest: 'uploads/' });

// قاموس الترجمة الموسّع
const translationDictionary = {
  'malware': 'برمجية خبيثة (Malware)',
  'trojan': 'حصان طروادة (Trojan)',
  'worm': 'دودة (Worm)',
  'adware': 'برنامج إعلاني (Adware)',
  'spyware': 'برنامج تجسس (Spyware)',
  'riskware': 'برنامج خطر (Riskware)',
  'phishing': 'تصيّد (Phishing)',
  'backdoor': 'باب خلفي (Backdoor)',
  'ransomware': 'برنامج فدية (Ransomware)',
  'clean': 'نظيف',
  'undetected': 'غير مكتشف',
  'suspicious': 'مريب',
  'malicious': 'ضار',
  'timeout': 'انتهت المهلة',
  'harmless': 'غير ضار',
  'type-unsupported': 'نوع غير مدعوم',
  'failure': 'فشل في الفحص',
  'confirmed-timeout': 'انتهت المهلة المؤكدة',
  'no-result': 'لا توجد نتيجة',
  'false-positive': 'إيجابية زائفة',
  'potentially-unwanted': 'برنامج غير مرغوب فيه'
};

function translateTerm(term) {
  if (!term || typeof term !== 'string') return term;
  const lower = term.toLowerCase();
  return translationDictionary[lower] || term;
}

function extractSeverity(stats) {
  const total = stats.malicious + stats.suspicious;
  if (total >= 10) return 'خطير جداً';
  if (total >= 5) return 'خطير';
  if (total >= 1) return 'مريب';
  return 'آمن';
}

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
    if (!id) return res.json({ error: "فشل إرسال الرابط للتحليل. تحقق من صحة الرابط." });

    await new Promise(resolve => setTimeout(resolve, 5000));

    const resultResponse = await fetch(`https://www.virustotal.com/api/v3/analyses/${id}`, {
      headers: { 'x-apikey': apiKey }
    });

    const resultData = await resultResponse.json();
    const stats = resultData.data?.attributes?.stats;

    if (!stats) return res.json({ error: "فشل الحصول على نتيجة الفحص." });

    const harmful = stats.malicious + stats.suspicious > 0;
    const severity = extractSeverity(stats);

    const engines = resultData.data.attributes.results || {};
    const التفاصيل = Object.entries(engines)
      .filter(([_, val]) => val.result)
      .slice(0, 6)
      .map(([engine, val]) => ({
        المحرك: engine,
        النتيجة: translateTerm(val.result)
      }));

    res.json({
      النتيجة: harmful ? `ضار - درجة الخطورة: ${severity}` : 'نظيف',
      التفاصيل: التفاصيل.length > 0 ? التفاصيل : 'لم يتم الكشف عن تهديدات بواسطة المحركات الأساسية.'
    });

  } catch (e) {
    console.error("URL Error:", e);
    res.json({ error: "حدث خطأ أثناء فحص الرابط. يرجى المحاولة لاحقاً." });
  }
});

app.post('/scan-file', upload.single('file'), async (req, res) => {
  try {
    const file = req.file;
    const formData = new FormData();
    formData.append('file', fs.createReadStream(file.path));

    const uploadResponse = await fetch('https://www.virustotal.com/api/v3/files', {
      method: 'POST',
      headers: { 'x-apikey': apiKey },
      body: formData
    });

    const uploadData = await uploadResponse.json();
    const id = uploadData.data?.id;
    if (!id) return res.json({ error: "فشل رفع الملف للتحليل. تأكد من صحة الملف." });

    await new Promise(resolve => setTimeout(resolve, 5000));

    const resultResponse = await fetch(`https://www.virustotal.com/api/v3/analyses/${id}`, {
      headers: { 'x-apikey': apiKey }
    });

    const resultData = await resultResponse.json();
    const stats = resultData.data?.attributes?.stats;

    if (!stats) return res.json({ error: "فشل الحصول على نتيجة الفحص." });

    const harmful = stats.malicious + stats.suspicious > 0;
    const severity = extractSeverity(stats);

    const engines = resultData.data.attributes.results || {};
    const التفاصيل = Object.entries(engines)
      .filter(([_, val]) => val.result)
      .slice(0, 6)
      .map(([engine, val]) => ({
        المحرك: engine,
        النتيجة: translateTerm(val.result)
      }));

    res.json({
      النتيجة: harmful ? `ضار - درجة الخطورة: ${severity}` : 'نظيف',
      التفاصيل: التفاصيل.length > 0 ? التفاصيل : 'لم يتم الكشف عن تهديدات بواسطة المحركات الأساسية.'
    });

    fs.unlink(file.path, () => {});

  } catch (e) {
    console.error("File Error:", e);
    res.json({ error: "حدث خطأ أثناء فحص الملف. يرجى المحاولة لاحقاً." });
  }
});

app.get('/', (req, res) => {
  res.send('خدمة فحص الروابط والملفات تعمل بنجاح.');
});

app.listen(port, () => {
  console.log(`الخادم يعمل على المنفذ ${port}`);
});
