const axios = require("axios");
const OpenAI = require("openai");
const Anthropic = require("@anthropic-ai/sdk");
const { logger } = require("../middleware/logger");

const mode = process.env.AI_PROVIDER || "synthetic";
const parsedTimeoutMs = parseInt(process.env.AI_HTTP_TIMEOUT_MS || "8000", 10);
const requestTimeoutMs = Number.isFinite(parsedTimeoutMs) ? parsedTimeoutMs : 8000;

const syntheticUrl = process.env.AI_SYNTHETIC_ENGINE_URL;
const syntheticKey = process.env.AI_SYNTHETIC_API_KEY;

const openai = process.env.OPENAI_API_KEY
  ? new OpenAI({ apiKey: process.env.OPENAI_API_KEY, timeout: requestTimeoutMs })
  : null;

const anthropic = process.env.ANTHROPIC_API_KEY
  ? new Anthropic({
      apiKey: process.env.ANTHROPIC_API_KEY,
      maxRetries: 1,
      timeout: requestTimeoutMs
    })
  : null;

const httpClient = axios.create({
  timeout: requestTimeoutMs,
  maxContentLength: 5 * 1024 * 1024
});

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

const isTransientError = err => {
  if (err?.response?.status && err.response.status >= 500) return true;
  const transientCodes = new Set(["ECONNABORTED", "ENOTFOUND", "ECONNRESET", "ETIMEDOUT"]);
  return transientCodes.has(err?.code);
};

async function withRetry(fn, { retries = 1, delayMs = 300, shouldRetry = isTransientError } = {}) {
  let attempt = 0;
  let lastErr;
  while (attempt <= retries) {
    try {
      return await fn();
    } catch (err) {
      lastErr = err;
      if (attempt === retries || (shouldRetry && !shouldRetry(err))) {
        break;
      }
      await sleep(delayMs * (attempt + 1));
      attempt += 1;
    }
  }
  throw lastErr;
}

const toHttpError = (err, defaultMessage, defaultStatus = 502) => {
  if (err?.response) {
    const error = new Error(defaultMessage);
    error.status = err.response.status || defaultStatus;
    error.details = err.response.data;
    return error;
  }

  if (err?.code === "ECONNABORTED" || err?.name === "AbortError") {
    const error = new Error("AI provider timed out");
    error.status = 504;
    return error;
  }

  const error = new Error(defaultMessage);
  error.status = defaultStatus;
  return error;
};

async function sendSynthetic(command, payload, meta) {
  if (!syntheticUrl || !syntheticKey) {
    const error = new Error("Synthetic AI engine not configured");
    error.status = 503;
    throw error;
  }

  try {
    const res = await withRetry(
      () =>
        httpClient.post(
          syntheticUrl,
          { command, payload, meta },
          {
            headers: {
              "x-api-key": syntheticKey,
              "x-security-mode": process.env.AI_SECURITY_MODE || "strict"
            }
          }
        ),
      { retries: 1, delayMs: 300 }
    );
    return res.data;
  } catch (err) {
    logger.error({
      msg: "Synthetic AI engine request failed",
      provider: "synthetic",
      error: err.message,
      status: err.response?.status,
      code: err.code,
      data: err.response?.data
    });
    throw toHttpError(err, "Synthetic AI engine request failed");
  }
}

async function sendOpenAI(command, payload) {
  if (!openai) {
    const error = new Error("OpenAI not configured");
    error.status = 503;
    throw error;
  }

  try {
    const prompt = `You are an AI logistics agent.\nCommand: ${command}\nPayload: ${JSON.stringify(payload)}`;
    const res = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      max_tokens: 300,
      messages: [{ role: "user", content: prompt }]
    });
    return { provider: "openai", text: res.choices?.[0]?.message?.content };
  } catch (err) {
    logger.error({
      msg: "OpenAI request failed",
      provider: "openai",
      error: err.message,
      status: err.status || err.response?.status,
      code: err.code
    });
    throw toHttpError(err, "OpenAI request failed");
  }
}

async function sendAnthropic(command, payload) {
  if (!anthropic) {
    const error = new Error("Anthropic not configured");
    error.status = 503;
    throw error;
  }

  try {
    const prompt = `You are an AI logistics agent.\nCommand: ${command}\nPayload: ${JSON.stringify(payload)}`;
    const res = await anthropic.messages.create({
      model: "claude-3-haiku-20240307",
      max_tokens: 300,
      messages: [{ role: "user", content: prompt }]
    });
    return { provider: "anthropic", text: res.content?.[0]?.text };
  } catch (err) {
    logger.error({
      msg: "Anthropic request failed",
      provider: "anthropic",
      error: err.message,
      status: err.status || err.response?.status,
      code: err.code
    });
    throw toHttpError(err, "Anthropic request failed");
  }
}

async function sendCommand(command, payload = {}, meta = {}) {
  if (mode === "openai") return sendOpenAI(command, payload);
  if (mode === "anthropic") return sendAnthropic(command, payload);
  return sendSynthetic(command, payload, meta);
}

module.exports = { sendCommand };
