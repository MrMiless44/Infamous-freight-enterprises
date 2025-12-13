const express = require("express");
const multer = require("multer");
const { sendCommand } = require("../services/aiSyntheticClient");
const {
  authenticate,
  requireScope,
  auditLog,
} = require("../middleware/security");
const {
  validateString,
  handleValidationErrors,
} = require("../middleware/validation");

const parsedMaxMb = parseInt(process.env.VOICE_MAX_FILE_SIZE_MB || "10", 10);
const maxFileSizeMb = Number.isFinite(parsedMaxMb) ? parsedMaxMb : 10;
const allowedMimeTypes = [
  "audio/mpeg",
  "audio/wav",
  "audio/x-wav",
  "audio/mp4",
  "audio/x-m4a",
  "audio/aac",
  "audio/webm",
  "audio/ogg",
];

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: maxFileSizeMb * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    if (allowedMimeTypes.includes(file.mimetype)) {
      return cb(null, true);
    }
    const err = new Error("Unsupported audio format");
    err.status = 400;
    return cb(err);
  },
});

const createError = (message, status = 400) => {
  const err = new Error(message);
  err.status = status;
  return err;
};

const router = express.Router();

router.post(
  "/voice/ingest",
  authenticate,
  requireScope("voice:ingest"),
  auditLog,
  upload.single("audio"),
  async (req, res, next) => {
    if (!req.file) return next(createError("audio required", 400));

    try {
      const transcript = "(simulated) Driver says: optimize route to Chicago";
      const result = await sendCommand("voice.input", { transcript });
      res.json({ ok: true, transcript, ai: result });
    } catch (err) {
      next(err);
    }
  },
);

router.post(
  "/voice/command",
  authenticate,
  requireScope("voice:command"),
  auditLog,
  [validateString("text", { min: 1, max: 1000 }), handleValidationErrors],
  async (req, res, next) => {
    const { text } = req.body || {};

    try {
      const result = await sendCommand("voice.command", { text });
      res.json({ ok: true, result });
    } catch (err) {
      next(err);
    }
  },
);

module.exports = router;
