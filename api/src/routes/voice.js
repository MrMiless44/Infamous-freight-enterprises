const express = require('express');
const multer = require('multer');
const { limiters, authenticate, requireScope, auditLog } = require('../middleware/security');

const router = express.Router();

// Configure Multer for audio uploads
const VOICE_MAX_FILE_SIZE_MB = parseInt(process.env.VOICE_MAX_FILE_SIZE_MB || '10', 10);
const upload = multer({
    limits: {
        fileSize: VOICE_MAX_FILE_SIZE_MB * 1024 * 1024, // MB to bytes
    },
    fileFilter: (req, file, cb) => {
        const allowedMimeTypes = ['audio/mpeg', 'audio/wav', 'audio/ogg', 'audio/webm'];
        if (allowedMimeTypes.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error('Invalid audio format. Allowed: MP3, WAV, OGG, WEBM'));
        }
    },
});

/**
 * POST /api/voice/ingest
 * Upload and process voice audio file
 * Scope: voice:ingest
 */
router.post(
    '/voice/ingest',
    limiters.ai,
    authenticate,
    requireScope('voice:ingest'),
    upload.single('audio'),
    auditLog,
    async (req, res, next) => {
        try {
            if (!req.file) {
                return res.status(400).json({
                    ok: false,
                    error: 'No audio file uploaded',
                });
            }

            // TODO: Process audio (e.g., transcribe with Whisper)
            const result = {
                ok: true,
                file: {
                    originalName: req.file.originalname,
                    size: req.file.size,
                    mimetype: req.file.mimetype,
                },
                transcription: 'Audio transcription not yet implemented',
                timestamp: new Date().toISOString(),
            };

            res.json(result);
        } catch (err) {
            next(err);
        }
    }
);

/**
 * POST /api/voice/command
 * Process voice command from text
 * Scope: voice:command
 */
router.post(
    '/voice/command',
    limiters.ai,
    authenticate,
    requireScope('voice:command'),
    auditLog,
    async (req, res, next) => {
        try {
            const { text } = req.body;

            if (!text) {
                return res.status(400).json({
                    ok: false,
                    error: 'Text command is required',
                });
            }

            // TODO: Process voice command
            const result = {
                ok: true,
                command: text,
                result: 'Voice command processing not yet implemented',
                timestamp: new Date().toISOString(),
            };

            res.json(result);
        } catch (err) {
            next(err);
        }
    }
);

module.exports = router;
