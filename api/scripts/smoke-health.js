#!/usr/bin/env node

const healthUrl = process.env.HEALTH_URL || "http://localhost/api/health";

(async () => {
  try {
    const res = await fetch(healthUrl);
    if (!res.ok) {
      throw new Error(`Unexpected status ${res.status}`);
    }

    const json = await res.json();
    if (!json.ok) {
      throw new Error(`Health endpoint returned: ${JSON.stringify(json)}`);
    }

    if (!json.service || typeof json.service !== "string") {
      throw new Error("Health response missing required 'service' string");
    }

    if (!json.version || typeof json.version !== "string") {
      throw new Error("Health response missing required 'version' string");
    }

    if (json.timestamp !== undefined) {
      const timestamp = Date.parse(json.timestamp);
      if (Number.isNaN(timestamp)) {
        throw new Error("Health response includes an invalid 'timestamp'");
      }
    }

    console.log("✅ Health smoke test passed", json);
  } catch (error) {
    console.error("Health smoke test failed:", error);
    process.exit(1);
  }
})();
