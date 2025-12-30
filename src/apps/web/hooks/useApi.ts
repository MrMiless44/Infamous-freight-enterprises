export function resolveApiBase(): string {
  const raw =
    process.env.NEXT_PUBLIC_API_URL || process.env.NEXT_PUBLIC_API_BASE_URL;

  if (!raw) {
    throw new Error(
      "API base URL is not configured. Set NEXT_PUBLIC_API_URL (or NEXT_PUBLIC_API_BASE_URL).",
    );
  }
  const trimmed = raw.replace(/\/+$/, "");

  // Try to treat value as an absolute URL first
  try {
    const url = new URL(trimmed);
    const pathname = url.pathname || "/";

    // If no meaningful path was provided, default to /api
    if (pathname === "/") {
      url.pathname = "/api";
      // Normalize: remove trailing slash except the one after /api
      return url.toString().replace(/\/+$/, "");
    }

    // A non-root path was provided (e.g. /api, /api/v1) – respect it as-is
    // but return the normalized URL string from the URL object for consistency
    return url.toString().replace(/\/+$/, "");
  } catch {
    // Not an absolute URL (likely a relative path); fall through to relative handling
  }

  // Relative path handling
  if (trimmed === "" || trimmed === "/") {
    return "/api";
  }

  // If /api already appears as a path segment, don't append it again
  if (trimmed.endsWith("/api") || trimmed.includes("/api/")) {
    return trimmed;
  }
  return `${trimmed}/api`;
}

export function useApi() {
  const base = resolveApiBase();

  function buildHeaders(custom?: HeadersInit) {
    const headers: HeadersInit = { ...(custom || {}) };
    if (typeof window !== "undefined") {
      const token = window.localStorage.getItem("authToken");
      if (token) {
        (headers as Record<string, string>).Authorization = `Bearer ${token}`;
      }
    }
    return headers;
  }

  async function get(path: string) {
    const res = await fetch(base + path, {
      headers: buildHeaders(),
    });
    if (!res.ok) throw new Error(await res.text());
    return res.json();
  }

  async function post(path: string, body?: unknown) {
    const res = await fetch(base + path, {
      method: "POST",
      headers: buildHeaders({ "Content-Type": "application/json" }),
      body: body ? JSON.stringify(body) : undefined,
    });
    if (!res.ok) throw new Error(await res.text());
    return res.json();
  }

  return { get, post };
}
