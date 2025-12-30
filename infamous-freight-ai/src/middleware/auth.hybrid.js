const jwt = require("jsonwebtoken");

module.exports = function authHybrid(req, res, next) {
    try {
        const apiKey = req.headers["x-api-key"];
        const authHeader = req.headers.authorization;

        if (apiKey === process.env.AI_SYNTHETIC_API_KEY) {
            req.auth = {
                mode: "api-key",
                subject: "system",
                scopes: ["ai:query", "data:read"]
            };
            return next();
        }

        if (authHeader?.startsWith("Bearer ")) {
            const token = authHeader.slice(7);
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            req.auth = {
                mode: "jwt",
                subject: decoded.sub,
                scopes: decoded.scopes || []
            };
            return next();
        }

        return res.status(401).json({ error: "Unauthorized" });
    } catch {
        return res.status(401).json({ error: "Invalid token" });
    }
};
