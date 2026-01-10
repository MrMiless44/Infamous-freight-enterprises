#!/usr/bin/env node
const fetch = globalThis.fetch || require("node-fetch");

const API_BASE = process.env.PROD_API_BASE_URL || process.env.API_BASE_URL;
const WEB_BASE = process.env.PROD_WEB_BASE_URL || process.env.WEB_BASE_URL;
const SMOKE_ENDPOINTS = process.env.SMOKE_ENDPOINTS; // comma-separated list of paths (relative to API_BASE)

async function checkUrl(url, name, opts = {}) {
  try {
    const res = await fetch(url, opts);
    const text = await res.text().catch(() => "");
    if (res.status >= 200 && res.status < 300) {
      console.log(`${name} ok: ${res.status}`);
      return true;
    }
    console.error(`${name} failed: ${res.status} ${text.slice(0, 200)}`);
    return false;
  } catch (err) {
    console.error(`${name} error:`, err.message || err);
    return false;
  }
}

async function run() {
  let ok = true;
  if (API_BASE) {
    const apiHealth = `${API_BASE.replace(/\/$/, "")}/api/health`;
    ok = (await checkUrl(apiHealth, "API /health")) && ok;
  }
  if (WEB_BASE) {
    const webRoot = `${WEB_BASE.replace(/\/$/, "")}/`;
    ok = (await checkUrl(webRoot, "Web /")) && ok;
  }

  if (SMOKE_ENDPOINTS && API_BASE) {
    const endpoints = SMOKE_ENDPOINTS.split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    for (const ep of endpoints) {
      const full = ep.startsWith("http")
        ? ep
        : `${API_BASE.replace(/\/$/, "")}/${ep.replace(/^\//, "")}`;
      ok = (await checkUrl(full, `Smoke ${ep}`)) && ok;
    }
  }

  if (!ok) process.exit(1);
  console.log("Extended smoke tests passed");
  process.exit(0);
}

run();
