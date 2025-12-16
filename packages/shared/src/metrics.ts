import client from "prom-client";

export const register = new client.Registry();

const httpDuration = new client.Histogram({
  name: "http_request_duration_seconds",
  help: "Response time in seconds",
  labelNames: ["method", "route", "status"],
  registers: [register],
});

register.registerMetric(httpDuration);
client.collectDefaultMetrics({ register });

export function metricsMiddleware(req, res, next) {
  const end = httpDuration.startTimer();
  res.on("finish", () => {
    end({ method: req.method, route: req.path, status: res.statusCode });
  });
  next();
}
