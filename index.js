const express = require("express");
const cors = require("cors");
const multer = require("multer");
const fetch = require("node-fetch");
require("dotenv").config();

const app = express();
const upload = multer();
app.use(cors());
app.use(express.json());

const VT_API_KEY = process.env.VT_API_KEY;

app.post("/scan-url", async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: "الرابط مطلوب" });

  try {
    const submitRes = await fetch("https://www.virustotal.com/api/v3/urls", {
      method: "POST",
      headers: {
        "x-apikey": VT_API_KEY,
        "content-type": "application/x-www-form-urlencoded",
      },
      body: `url=${encodeURIComponent(url)}`,
    });
    const submitData = await submitRes.json();
    const analysisId = submitData.data.id;

    const resultRes = await fetch(
      `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
      { headers: { "x-apikey": VT_API_KEY } }
    );
    const resultData = await resultRes.json();

    const stats = resultData.data.attributes.stats;
    res.json({
      "نتائج الفحص": {
        "سليم": stats.harmless,
        "مريب": stats.suspicious,
        "ضار": stats.malicious,
        "غير معروف": stats.undetected,
      },
    });
  } catch (err) {
    res.status(500).json({ error: "حدث خطأ أثناء الفحص." });
  }
});

app.post("/scan-file", upload.single("file"), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: "الملف مطلوب" });

  try {
    const form = new FormData();
    form.append("file", req.file.buffer, req.file.originalname);

    const scanRes = await fetch("https://www.virustotal.com/api/v3/files", {
      method: "POST",
      headers: { "x-apikey": VT_API_KEY },
      body: form,
    });

    const scanData = await scanRes.json();
    const analysisId = scanData.data.id;

    const resultRes = await fetch(
      `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
      { headers: { "x-apikey": VT_API_KEY } }
    );
    const resultData = await resultRes.json();

    const stats = resultData.data.attributes.stats;
    res.json({
      "نتائج الفحص": {
        "سليم": stats.harmless,
        "مريب": stats.suspicious,
        "ضار": stats.malicious,
        "غير معروف": stats.undetected,
      },
    });
  } catch (err) {
    res.status(500).json({ error: "حدث خطأ أثناء فحص الملف." });
  }
});

app.listen(process.env.PORT || 3000, () =>
  console.log("الخادم يعمل بنجاح")
);
