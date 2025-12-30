module.exports = function scopeGuard(requiredScopes = []) {
    return (req, res, next) => {
        const scopes = req.auth?.scopes || [];
        const ok = requiredScopes.every(s => scopes.includes(s));
        if (!ok) {
            return res.status(403).json({ error: "Forbidden" });
        }
        next();
    };
};
