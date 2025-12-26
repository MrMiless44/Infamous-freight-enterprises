import type { NextApiRequest, NextApiResponse } from "next";

// Proxies requests from /api/proxy/* to the backend API
// Base URL is taken from NEXT_PUBLIC_API_BASE_URL
const API_BASE = (process.env.NEXT_PUBLIC_API_BASE_URL || "").replace(
  /\/$/,
  "",
);

function buildTargetUrl(req: NextApiRequest, base: string) {
  const rawQuery =
    req.url && req.url.includes("?")
      ? req.url.substring(req.url.indexOf("?"))
      : "";
  const segments = req.query.path;
  const path = Array.isArray(segments) ? segments.join("/") : segments || "";
  return `${base}/${path}${rawQuery}`;
}

function forwardableHeaders(req: NextApiRequest) {
  const headers = new Headers();
  for (const [key, value] of Object.entries(req.headers)) {
    if (value == null) continue;
    // Skip hop-by-hop and Next internal headers
    const lower = key.toLowerCase();
    if (
      [
        "host",
        "connection",
        "content-length",
        "accept-encoding",
        "x-vercel-id",
        "x-vercel-deployment-url",
      ].includes(lower)
    ) {
      continue;
    }
    // Multiple values can be string[]
    if (Array.isArray(value)) {
      headers.set(key, value.join(", "));
    } else {
      headers.set(key, value as string);
    }
  }
  return headers;
}

export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse,
) {
  if (!API_BASE) {
    res.status(500).json({
      ok: false,
      error: "API base URL not configured (set NEXT_PUBLIC_API_BASE_URL)",
    });
    return;
  }

  const url = buildTargetUrl(req, API_BASE);
  const headers = forwardableHeaders(req);

  let body: BodyInit | undefined;
  const method = (req.method || "GET").toUpperCase();

  if (method !== "GET" && method !== "HEAD") {
    // If Next parsed body as object, serialize JSON; otherwise pass through string
    const contentType = (req.headers["content-type"] || "").toString();
    if (typeof req.body === "string") {
      body = req.body;
    } else if (req.body && contentType.includes("application/json")) {
      body = JSON.stringify(req.body);
      // Ensure content-type header present
      if (!headers.has("content-type"))
        headers.set("content-type", "application/json");
    } else {
      // Fallback: no body (for unsupported encodings in this simple proxy)
      body = undefined;
    }
  }

  try {
    const resp = await fetch(url, {
      method,
      headers,
      body,
    });

    // Copy status and headers
    res.status(resp.status);
    resp.headers.forEach((value, key) => {
      // Avoid setting duplicate or forbidden headers
      if (["transfer-encoding"].includes(key.toLowerCase())) return;
      res.setHeader(key, value);
    });

    // Send body
    const buffer = Buffer.from(await resp.arrayBuffer());
    res.send(buffer);
  } catch (err: any) {
    res.status(502).json({
      ok: false,
      error: "Proxy request failed",
      detail: err?.message || String(err),
    });
  }
}

export const config = {
  api: {
    // Keep default bodyParser (true). If you need raw bodies (e.g., webhooks), set to false and handle streams.
    bodyParser: true,
    externalResolver: true,
  },
};
