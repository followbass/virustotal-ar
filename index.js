const express = require("express");
const axios = require("axios");
const cors = require("cors");
const multer = require("multer");
const FormData = require("form-data");
const fs = require("fs");

const app = express();
const upload = multer({ dest: "uploads/" });

app.use(cors());
app.use(express.json());

const API_KEY = process.env.VIRUSTOTAL_API_KEY;

// فحص الروابط
app.post("/scan-url", async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: "يرجى إرسال رابط للفحص." });

  try {
    // إرسال الرابط للفحص
    const response = await axios.post(
      "https://www.virustotal.com/api/v3/urls",
      `url=${encodeURIComponent(url)}`,
      {
        headers: {
          "x-apikey": API_KEY,
          "Content-Type": "application/x-www-form-urlencoded",
        },
      }
    );

    const analysisId = response.data.data.id;

    // جلب نتائج التحليل
    const result = await axios.get(
      `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
      {
        headers: { "x-apikey": API_KEY },
      }
    );

    res.json(result.data);
  } catch (error) {
    res.status(500).json({ error: "حدث خطأ أثناء الفحص", details: error.message });
  }
});

// فحص الملفات
app.post("/scan-file", upload.single("file"), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: "يرجى إرسال ملف للفحص." });

  try {
    const form = new FormData();
    form.append("file", fs.createReadStream(req.file.path));

    const response = await axios.post(
      "https://www.virustotal.com/api/v3/files",
      form,
      {
        headers: {
          ...form.getHeaders(),
          "x-apikey": API_KEY,
        },
      }
    );

    const analysisId = response.data.data.id;

    // جلب نتائج التحليل
    const result = await axios.get(
      `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
      {
        headers: { "x-apikey": API_KEY },
      }
    );

    res.json(result.data);
  } catch (error) {
    res.status(500).json({ error: "حدث خطأ أثناء الفحص", details: error.message });
  } finally {
    // حذف الملف المؤقت
    fs.unlink(req.file.path, (err) => {
      if (err) console.error("خطأ في حذف الملف المؤقت:", err);
    });
  }
});

app.get("/", (req, res) => {
  res.send("VirusTotal API Proxy is Running");
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
