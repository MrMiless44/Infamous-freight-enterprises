const express = require("express");
const { z } = require("zod");
const auth = require("../middleware/auth.hybrid");
const audit = require("../middleware/audit");
const scopeGuard = require("../middleware/scopeGuard");
const { sendCommand } = require("../ai/services/aiSyntheticClient");

const router = express.Router();

const Schema = z.object({
    command: z.string().min(1),
    payload: z.record(z.any()).optional()
});

router.post("/command", auth, scopeGuard(["ai:query", "data:read"]), audit, async (req, res) => {
    try {
        const { command, payload } = Schema.parse(req.body);
        const result = await sendCommand(command, payload, req.auth);
        res.json({ ok: true, result });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

module.exports = router;
