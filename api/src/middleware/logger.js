const pino = require("pino");
const pinoHttp = require("pino-http");

const level = process.env.LOG_LEVEL || "info";
const isProduction = process.env.NODE_ENV === "production";
let transport;

if (!isProduction) {
  const hasPretty = (() => {
    try {
      require.resolve("pino-pretty");
      return true;
    } catch (_err) {
      return false;
    }
  })();

  if (hasPretty) {
    transport = {
      target: "pino-pretty",
      options: {
        colorize: true,
        translateTime: "SYS:standard",
        ignore: "pid,hostname",
      },
    };
  }
}

const logger = pino({
  level,
  transport,
});

const httpLogger = pinoHttp({
  logger,
  customLogLevel: (req, res, err) => {
    if (res.statusCode >= 400 && res.statusCode < 500) {
      return "warn";
    } else if (res.statusCode >= 500 || err) {
      return "error";
    }
    return "info";
  },
});

module.exports = { logger, httpLogger };
