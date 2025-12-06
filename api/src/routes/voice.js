const express = require("express");
const multer = require("multer");
const { sendCommand } = require("../services/aiSyntheticClient");

const upload = multer({ storage: multer.memoryStorage() });
const router = express.Router();

router.post("/voice/ingest", upload.single("audio"), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: "audio required" });

  try {
    const transcript = "(simulated) Driver says: optimize route to Chicago";
    const result = await sendCommand("voice.input", { transcript });
    res.json({ ok: true, transcript, ai: result });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

router.post("/voice/command", async (req, res) => {
  const { text } = req.body || {};
  if (!text) return res.status(400).json({ error: "text required" });

  try {
    const result = await sendCommand("voice.command", { text });
    res.json({ ok: true, result });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
