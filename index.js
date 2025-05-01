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

app.use(cors()); // بدون أي قيود
app.use(express.json());
app.use(express.static("public"));

// فحص الروابط
app.post("/scan-url", async (req, res) => {
  const { url } = req.body;
  try {
    const response = await fetch(`${BASE_URL}/urls`, {
      method: "POST",
      headers: {
        "x-apikey": API_KEY,
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: `url=${encodeURIComponent(url)}`
    });

    const data = await response.json();
    const id = data.data.id;

    const result = await fetch(`${BASE_URL}/urls/${id}`, {
      headers: { "x-apikey": API_KEY }
    });

    const final = await result.json();
    res.json(final);
  } catch (error) {
    console.error("URL scan error:", error);
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
        "x-apikey": API_KEY,
        "Content-Type": "application/octet-stream"
      },
      body: buffer
    });

    const data = await response.json();
    const id = data.data.id;

    const result = await fetch(`${BASE_URL}/files/${id}`, {
      headers: { "x-apikey": API_KEY }
    });

    const final = await result.json();
    res.json(final);
  } catch (error) {
    console.error("File scan error:", error);
    res.status(500).json({ error: "حدث خطأ أثناء فحص الملف." });
  } finally {
    fs.unlinkSync(filePath); // حذف الملف المؤقت
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
