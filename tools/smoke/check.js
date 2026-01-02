#!/usr/bin/env node
const fetch = globalThis.fetch || require('node-fetch');

const API_BASE = process.env.PROD_API_BASE_URL || process.env.API_BASE_URL;
const WEB_BASE = process.env.PROD_WEB_BASE_URL || process.env.WEB_BASE_URL;

if (!API_BASE && !WEB_BASE) {
    console.error('Missing PROD_API_BASE_URL or PROD_WEB_BASE_URL environment variables');
    process.exit(2);
}

async function checkUrl(url, name) {
    try {
        const res = await fetch(url, { method: 'GET' });
        if (res.status >= 200 && res.status < 300) {
            console.log(`${name} ok: ${res.status}`);
            return true;
        }
        console.error(`${name} failed: ${res.status}`);
        return false;
    } catch (err) {
        console.error(`${name} error:`, err.message || err);
        return false;
    }
}

(async () => {
    let ok = true;
    if (API_BASE) {
        const apiHealth = `${API_BASE.replace(/\/$/, '')}/api/health`;
        ok = (await checkUrl(apiHealth, 'API /health')) && ok;
    }
    if (WEB_BASE) {
        const webRoot = `${WEB_BASE.replace(/\/$/, '')}/`;
        ok = (await checkUrl(webRoot, 'Web /')) && ok;
    }

    if (!ok) process.exit(1);
    console.log('Smoke tests passed');
    process.exit(0);
})();
