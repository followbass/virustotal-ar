const express = require("express");
const fetch = require("node-fetch");
const cors = require("cors");
const multer = require("multer");
const fs = require("fs");
require("dotenv").config();

const app = express();
const upload = multer({ dest: "uploads/" });
const PORT = process.env.PORT || 3000;
const API_KEY = process.env.VIRUSTOTAL_API_KEY;
const BASE_URL = "https://www.virustotal.com/api/v3";

app.use(cors());
app.use(express.json());
app.use(express.static("public"));

// دالة لتحليل النتائج واستخراج أهم 6 محركات كشفت التهديد
function getArabicSummary(data) {
  const engines = data.data.attributes.last_analysis_results;
  const detected = Object.entries(engines)
    .filter(([_, result]) => result.category === "malicious")
    .slice(0, 6)
    .map(([engine, result]) => ({
      المحرك: engine,
      النتيجة: result.result
    }));

  if (detected.length === 0) {
    return { النتيجة: "آمن", التفاصيل: [] };
  } else {
    return { النتيجة: "ضار", التفاصيل: detected };
  }
}

// فحص الروابط
app.post("/scan-url", async (req, res) => {
  const { url } = req.body;

  try {
    const submitResponse = await fetch(`${BASE_URL}/urls`, {
      method: "POST",
      headers: {
        "x-apikey": API_KEY,
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: `url=${encodeURIComponent(url)}`
    });

    const submitData = await submitResponse.json();
    const urlId = submitData.data.id.replace(/^.*-/, ""); // تصحيح معرف URL

    const result = await fetch(`${BASE_URL}/urls/${urlId}`, {
      headers: { "x-apikey": API_KEY }
    });

    const final = await result.json();
    const summary = getArabicSummary(final);
    res.json(summary);
  } catch (error) {
    console.error("خطأ في فحص الرابط:", error.message);
    res.status(500).json({ error: "حدث خطأ أثناء الفحص." });
  }
});

// فحص الملفات
app.post("/scan-file", upload.single("file"), async (req, res) => {
  const filePath = req.file.path;

  try {
    const buffer = fs.readFileSync(filePath);

    const response = await fetch(`${BASE_URL}/files`, {
      method: "POST",
      headers: {
        "x-apikey": API_KEY
      },
      body: buffer
    });

    const data = await response.json();
    const id = data.data.id;

    // الانتظار 5 ثوانٍ لضمان جاهزية التحليل
    await new Promise(resolve => setTimeout(resolve, 5000));

    const result = await fetch(`${BASE_URL}/files/${id}`, {
      headers: { "x-apikey": API_KEY }
    });

    const final = await result.json();
    const summary = getArabicSummary(final);
    res.json(summary);
  } catch (error) {
    console.error("خطأ في فحص الملف:", error.message);
    res.status(500).json({ error: "حدث خطأ أثناء فحص الملف." });
  } finally {
    fs.unlinkSync(filePath);
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
