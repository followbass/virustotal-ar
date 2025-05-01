// index.js const express = require("express"); const fetch = require("node-fetch"); const cors = require("cors"); const multer = require("multer"); const fs = require("fs"); require("dotenv").config();

const app = express(); const upload = multer({ dest: "uploads/" }); const PORT = process.env.PORT || 3000; const API_KEY = process.env.VIRUSTOTAL_API_KEY; const BASE_URL = "https://www.virustotal.com/api/v3";

app.use(cors()); app.use(express.json()); app.use(express.static("public"));

function ترجمة_النتائج(data) { const stats = data.data.attributes.last_analysis_stats; const النتائج = { "نظيف": stats.harmless, "مشبوه": stats.suspicious, "ضار": stats.malicious, "غير معروف": stats.undetected };

const التفاصيل = Object.entries(data.data.attributes.last_analysis_results) .filter(([_, value]) => value.category === "malicious") .slice(0, 6) .map(([name, value]) => ({ المحرك: name, النتيجة: value.result, }));

return { نوع: data.data.type, الاحصائيات: النتائج, التفاصيل: التفاصيل.length ? التفاصيل : "لا توجد نتائج ضارة." }; }

// فحص الروابط app.post("/scan-url", async (req, res) => { const { url } = req.body; try { const submitResponse = await fetch(${BASE_URL}/urls, { method: "POST", headers: { "x-apikey": API_KEY, "Content-Type": "application/x-www-form-urlencoded" }, body: url=${encodeURIComponent(url)} });

const submitData = await submitResponse.json();
const encodedUrl = Buffer.from(url).toString("base64").replace(/=+$/, "");

const result = await fetch(`${BASE_URL}/urls/${encodedUrl}`, {
  headers: { "x-apikey": API_KEY }
});

const final = await result.json();
res.json(ترجمة_النتائج(final));

} catch (error) { res.status(500).json({ error: "حدث خطأ أثناء فحص الرابط." }); } });

// فحص الملفات app.post("/scan-file", upload.single("file"), async (req, res) => { const filePath = req.file.path;

try { const buffer = fs.readFileSync(filePath);

const response = await fetch(`${BASE_URL}/files`, {
  method: "POST",
  headers: {
    "x-apikey": API_KEY
  },
  body: buffer
});

const data = await response.json();
const id = data.data.id;

const result = await fetch(`${BASE_URL}/files/${id}`, {
  headers: { "x-apikey": API_KEY }
});

const final = await result.json();
res.json(ترجمة_النتائج(final));

} catch (error) { res.status(500).json({ error: "حدث خطأ أثناء فحص الملف." }); } finally { fs.unlinkSync(filePath); } });

app.listen(PORT, () => { console.log(Server running on port ${PORT}); });
