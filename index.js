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

// الترجمة
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

function isThreat(term) {
  const threatIndicators = ['malicious', 'phishing', 'malware', 'trojan', 'spyware', 'backdoor', 'worm', 'ransomware', 'suspicious', 'riskware', 'potentially-unwanted'];
  return threatIndicators.includes(term.toLowerCase());
}

function extractThreats(results) {
  return Object.entries(results)
    .filter(([_, val]) => val.result && isThreat(val.result))
    .map(([engine, val]) => ({
      المحرك: engine,
      النتيجة: translateTerm(val.result)
    }));
}

// استرجاع نتائج التحليل مع إعادة المحاولة البسيطة
async function getAnalysisWithRetry(id) {
  const fetchResult = async () => {
    const res = await fetch(`https://www.virustotal.com/api/v3/analyses/${id}`, {
      headers: { 'x-apikey': apiKey }
    });
    return res.json();
  };

  let resultData = await fetchResult();
  let stats = resultData?.data?.attributes?.stats;

  if (!stats) {
    await new Promise(resolve => setTimeout(resolve, 3000));
    resultData = await fetchResult();
    stats = resultData?.data?.attributes?.stats;
  }

  return stats ? resultData : null;
}

// فحص الروابط
app.post('/scan-url', async (req, res) => {
  const { url } = req.body;

  if (!url || typeof url !== 'string') {
    return res.status(400).json({ error: "يرجى إدخال رابط صالح." });
  }

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

    if (!id) {
      return res.status(503).json({ error: "فشل إرسال الرابط للتحليل." });
    }

    await new Promise(resolve => setTimeout(resolve, 5000));
    const resultData = await getAnalysisWithRetry(id);

    if (!resultData) {
      return res.status(504).json({ error: "انتهت المهلة في انتظار نتائج الفحص." });
    }

    const stats = resultData.data.attributes.stats;
    const engines = resultData.data.attributes.results || {};
    const harmful = stats.malicious + stats.suspicious > 0;

    if (!harmful) {
      return res.status(200).json({ النتيجة: 'نظيف' });
    }

    const التهديدات = extractThreats(engines);
    return res.status(200).json({
      النتيجة: 'ضار',
      التفاصيل: التهديدات.length > 0 ? التهديدات : 'تم الكشف عن ضرر لكن بدون تفاصيل محددة.'
    });

  } catch (e) {
    console.error("URL Error:", e);
    return res.status(500).json({ error: "حدث خطأ أثناء فحص الرابط." });
  }
});

// فحص الملفات
app.post('/scan-file', upload.single('file'), async (req, res) => {
  try {
    const file = req.file;
    if (!file) {
      return res.status(400).json({ error: "يرجى رفع ملف صالح." });
    }

    const formData = new FormData();
    formData.append('file', fs.createReadStream(file.path));

    const uploadResponse = await fetch('https://www.virustotal.com/api/v3/files', {
      method: 'POST',
      headers: { 'x-apikey': apiKey },
      body: formData
    });

    const uploadData = await uploadResponse.json();
    const id = uploadData.data?.id;

    if (!id) {
      fs.unlink(file.path, () => {});
      return res.status(503).json({ error: "فشل رفع الملف للتحليل." });
    }

    await new Promise(resolve => setTimeout(resolve, 5000));
    const resultData = await getAnalysisWithRetry(id);

    fs.unlink(file.path, () => {});

    if (!resultData) {
      return res.status(504).json({ error: "انتهت المهلة في انتظار نتائج الفحص." });
    }

    const stats = resultData.data.attributes.stats;
    const engines = resultData.data.attributes.results || {};
    const harmful = stats.malicious + stats.suspicious > 0;

    if (!harmful) {
      return res.status(200).json({ النتيجة: 'نظيف' });
    }

    const التهديدات = extractThreats(engines);
    return res.status(200).json({
      النتيجة: 'ضار',
      التفاصيل: التهديدات.length > 0 ? التهديدات : 'تم الكشف عن ضرر لكن بدون تفاصيل محددة.'
    });

  } catch (e) {
    console.error("File Error:", e);
    return res.status(500).json({ error: "حدث خطأ أثناء فحص الملف." });
  }
});

app.get('/', (req, res) => {
  res.send('خدمة فحص الروابط والملفات تعمل بنجاح.');
});

app.listen(port, () => {
  console.log(`الخادم يعمل على المنفذ ${port}`);
});
