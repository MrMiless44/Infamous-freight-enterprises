module.exports = function audit(req, res, next) {
    const start = Date.now();
    res.on("finish", () => {
        console.log(
            `[AUDIT] ${req.method} ${req.originalUrl} ${res.statusCode} ${Date.now() - start}ms`
        );
    });
    next();
};
