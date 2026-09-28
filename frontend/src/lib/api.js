const TOKEN_KEY = "sc_token";

export function getToken() {
  try {
    return sessionStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

export function setToken(token) {
  try {
    if (token) sessionStorage.setItem(TOKEN_KEY, token);
    else sessionStorage.removeItem(TOKEN_KEY);
  } catch {
    /* storage unavailable (private mode) - the session simply won't survive a reload */
  }
}

export class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

async function parseError(res) {
  try {
    const data = await res.json();
    if (typeof data.detail === "string") return data.detail;
    if (Array.isArray(data.detail)) return data.detail.map((d) => d.msg).join(", ");
  } catch {
    /* not JSON */
  }
  return res.statusText || "Request failed";
}

/**
 * Fetch wrapper: JSON in/out, bearer token, consistent errors.
 * A 401 broadcasts "auth:expired" so the app can return to the sign-in screen.
 */
export async function api(path, { method = "GET", body, form, raw = false } = {}) {
  const headers = {};
  const token = getToken();
  if (token) headers.Authorization = `Bearer ${token}`;
  let payload;
  if (form) payload = form;
  else if (body !== undefined) {
    headers["Content-Type"] = "application/json";
    payload = JSON.stringify(body);
  }

  let res;
  try {
    res = await fetch(path, { method, headers, body: payload });
  } catch {
    throw new ApiError(0, "Can't reach the server. Check that the API is running.");
  }
  if (!res.ok) {
    const message = await parseError(res);
    if (res.status === 401 && token) window.dispatchEvent(new Event("auth:expired"));
    throw new ApiError(res.status, message);
  }
  if (raw) return res;
  const type = res.headers.get("content-type") || "";
  return type.includes("application/json") ? res.json() : res.text();
}

/** Save a response as a file. Returns false when downloads are unavailable (the demo preview). */
export async function downloadResponse(res, fallbackName) {
  if (import.meta.env.VITE_DEMO === "1") return false;
  const blob = await res.blob();
  const disposition = res.headers.get("content-disposition") || "";
  const match = /filename\*=UTF-8''([^;]+)|filename="?([^";]+)"?/i.exec(disposition);
  const name = match ? decodeURIComponent(match[1] || match[2]) : fallbackName;
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  return true;
}
