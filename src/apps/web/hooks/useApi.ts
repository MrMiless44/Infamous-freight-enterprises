export function useApi() {
  const base = (
    process.env.NEXT_PUBLIC_API_URL ||
    process.env.API_BASE_URL ||
    "/api"
  ).replace(/\/$/, "");

  const buildUrl = (path: string) => {
    if (!path.startsWith("/")) {
      return `${base}/${path}`;
    }
    return `${base}${path}`;
  };

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
    const res = await fetch(buildUrl(path), {
      headers: buildHeaders(),
    });
    if (!res.ok) throw new Error(await res.text());
    return res.json();
  }

  async function post(path: string, body?: unknown) {
    const res = await fetch(buildUrl(path), {
      method: "POST",
      headers: buildHeaders({ "Content-Type": "application/json" }),
      body: body ? JSON.stringify(body) : undefined,
    });
    if (!res.ok) throw new Error(await res.text());
    return res.json();
  }

  return { get, post };
}
