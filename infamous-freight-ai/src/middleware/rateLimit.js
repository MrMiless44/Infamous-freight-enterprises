const { RateLimiterMemory } = require("rate-limiter-flexible");

module.exports = function rateLimit({ points = 100, duration = 60 }) {
    const limiter = new RateLimiterMemory({ points, duration });

    return async (req, res, next) => {
        try {
            await limiter.consume(req.ip);
            next();
        } catch {
            res.status(429).json({ error: "Too many requests" });
        }
    };
};
