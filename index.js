const express = require("express");
const axios = require("axios");
const cors = require("cors");

const app = express();
app.use(cors());
app.use(express.json());

const API_KEY = process.env.VIRUSTOTAL_API_KEY;

// تحقق من رابط URL عبر VirusTotal
app.post("/scan-url", async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: "يرجى إرسال رابط للفحص." });

  try {
    // إرسال رابط للفحص
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

    // جلب نتائج الفحص
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

app.get("/", (req, res) => {
  res.send("VirusTotal API Proxy is Running");
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
