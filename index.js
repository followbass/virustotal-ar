const express = require("express");
const multer = require("multer");
const axios = require("axios");
const fs = require("fs");
require("dotenv").config();

const app = express();
const upload = multer({ dest: "uploads/" });

const API_KEY = process.env.VIRUSTOTAL_API_KEY;
const VT_BASE = "https://www.virustotal.com/api/v3";

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  next();
});

function translateResult(result) {
  return {
    "harmless": "غير ضار",
    "malicious": "ضار",
    "suspicious": "مشبوه",
    "undetected": "غير مكتشف",
    "timeout": "انتهت المهلة"
  }[result] || result;
}

// فحص رابط
app.post("/scan/url", async (req, res) => {
  try {
    const { url } = req.body;
    const { data } = await axios.post(
      `${VT_BASE}/urls`,
      new URLSearchParams({ url }),
      { headers: { "x-apikey": API_KEY, "Content-Type": "application/x-www-form-urlencoded" } }
    );

    const scanId = data.data.id;
    const result = await axios.get(`${VT_BASE}/analyses/${scanId}`, {
      headers: { "x-apikey": API_KEY }
    });

    const stats = result.data.data.attributes.stats;
    const translated = {};
    for (const [k, v] of Object.entries(stats)) {
      translated[translateResult(k)] = v;
    }

    res.json({ scan_id: scanId, stats: translated });
  } catch (error) {
    res.status(500).json({ error: "فشل في فحص الرابط", details: error.message });
  }
});

// فحص ملف
app.post("/scan/file", upload.single("file"), async (req, res) => {
  try {
    const file = req.file;
    const form = new FormData();
    form.append("file", fs.createReadStream(file.path));

    const response = await axios.post(`${VT_BASE}/files`, form, {
      headers: {
        ...form.getHeaders(),
        "x-apikey": API_KEY
      }
    });

    fs.unlinkSync(file.path); // حذف الملف المؤقت

    const scanId = response.data.data.id;
    const result = await axios.get(`${VT_BASE}/analyses/${scanId}`, {
      headers: { "x-apikey": API_KEY }
    });

    const stats = result.data.data.attributes.stats;
    const translated = {};
    for (const [k, v] of Object.entries(stats)) {
      translated[translateResult(k)] = v;
    }

    res.json({ scan_id: scanId, stats: translated });
  } catch (error) {
    res.status(500).json({ error: "فشل في فحص الملف", details: error.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("API is running on port", PORT);
});
