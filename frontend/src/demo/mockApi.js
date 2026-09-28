/**
 * In-browser mock of the FastAPI backend, used only by the demo build (VITE_DEMO=1).
 * Responses mirror backend/routers/*.py so the real UI runs unchanged with simulated data.
 * State lives in memory and resets on reload.
 */

// ── helpers ───────────────────────────────────────────────────────────────────
let seed = 7;
const rand = () => ((seed = (seed * 16807) % 2147483647) - 1) / 2147483646;
const pick = (arr) => arr[Math.floor(rand() * arr.length)];
const gauss = () => Math.sqrt(-2 * Math.log(rand() || 1e-9)) * Math.cos(2 * Math.PI * rand());
const pad = (n) => String(n).padStart(2, "0");
const stamp = (d) =>
  `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
const now = () => stamp(new Date());
const ago = (minutes) => stamp(new Date(Date.now() - minutes * 60000));
const cipher = () => "gAAAAABm" + Array.from({ length: 120 }, () => pick("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")).join("");

async function sha256(text) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

class HttpError extends Error {
  constructor(status, detail) {
    super(detail);
    this.status = status;
  }
}

// ── seed data ─────────────────────────────────────────────────────────────────
const users = {
  Admin: { role: "admin", password: "Admin@12345", pin: "1234", status: "active", reason: "", requested: false },
  alice: { role: "client", password: "Demo@1234", pin: "4821", status: "active", reason: "", requested: false },
  bob: { role: "client", password: "Demo@1234", pin: "7390", status: "active", reason: "", requested: false },
  carol: { role: "client", password: "Demo@1234", pin: "2468", status: "active", reason: "", requested: false },
};

let nextId = 1;
const messages = [];
function addMessage(sender, receiver, text, minutesAgo, status, decrypted = false) {
  messages.push({
    id: nextId++, sender, receiver, text, encrypted: cipher(), decrypted,
    timestamp: ago(minutesAgo), status, read_at: status === "read" ? ago(minutesAgo - 5) : null,
  });
}
addMessage("alice", "bob", "Hi Bob, the quarterly report is ready for review.", 720, "read", true);
addMessage("bob", "alice", "Thanks! I'll send the signed copy this afternoon.", 700, "read", true);
addMessage("Admin", "alice", "Reminder: please rotate your PIN this week.", 400, "read", true);
addMessage("alice", "Admin", "Done, PIN updated.", 380, "delivered");
addMessage("bob", "Admin", "Can you review the new firewall rules before Friday?", 90, "delivered");
addMessage("carol", "Admin", "The VPN certificate expires on the 30th.", 35, "sent");
addMessage("Admin", "bob", "Quarterly audit starts Monday at 09:00.", 20, "sent");

const logs = [];
const ACTIONS = [
  ["INFO", 30, (u) => `Logged in from 10.0.${Math.floor(rand() * 9)}.${10 + Math.floor(rand() * 200)}`],
  ["INFO", 22, (u) => `Sent message/file to ${pick(Object.keys(users).filter((x) => x !== u))}`],
  ["INFO", 16, () => `Decrypted and verified message ${10 + Math.floor(rand() * 90)}`],
  ["INFO", 6, () => `Successfully decrypted & downloaded: ${pick(["contract.pdf", "budget.xlsx", "keys.txt", "policy.docx"])}`],
  ["WARNING", 8, () => "Failed login attempt"],
  ["WARNING", 4, () => `Incorrect PIN attempt for message ${10 + Math.floor(rand() * 90)}`],
  ["WARNING", 2, () => `Failed decryption attempt on message ${10 + Math.floor(rand() * 90)}`],
  ["ALERT", 1.2, () => `Tampering detected on encrypted message ${10 + Math.floor(rand() * 90)}`],
  ["ALERT", 0.6, () => "Account locked after 5 failed login attempts"],
  ["CRITICAL", 0.35, () => "[DURESS ALERT] User entered reversed PIN during: decrypt message 42"],
];
const TOTAL_WEIGHT = ACTIONS.reduce((s, a) => s + a[1], 0);
function randomAction() {
  let r = rand() * TOTAL_WEIGHT;
  for (const a of ACTIONS) if ((r -= a[1]) <= 0) return a;
  return ACTIONS[0];
}
for (let day = 29; day >= 0; day--) {
  const count = 4 + Math.floor(rand() * (day < 3 ? 14 : 9));
  for (let i = 0; i < count; i++) {
    const u = pick(Object.keys(users));
    const [severity, , make] = randomAction();
    logs.push({ username: u, action: make(u), severity, timestamp: ago(day * 1440 + Math.floor(rand() * 1400)) });
  }
}
logs.sort((a, b) => a.timestamp.localeCompare(b.timestamp)).forEach((l, i) => (l.id = i + 1));
function log(username, action, severity = "INFO") {
  logs.push({ id: logs.length + 1, username, action, severity, timestamp: now() });
}

const files = [
  { id: 1, sender: "alice", receiver: "bob", name: "contract.pdf", status: "safe", uploaded: ago(2900) },
  { id: 2, sender: "bob", receiver: "Admin", name: "firewall-rules.conf", status: "safe", uploaded: ago(180) },
  { id: 3, sender: "Admin", receiver: "bob", name: "policy.docx", status: "tampered", uploaded: ago(1500) },
  { id: 4, sender: "carol", receiver: "Admin", name: "vpn-cert.pem", status: "safe", uploaded: ago(40) },
];
for (const f of files) {
  f.hash = await sha256(f.name + f.uploaded);
  f.checked = f.uploaded;
  f.content = `Demo file: ${f.name}\nSent by ${f.sender} to ${f.receiver}.\n`;
}

let broadcast = { admin: "Admin", message: "Scheduled key rotation on Sunday at 02:00 UTC.", timestamp: ago(300) };
const devices = {
  Admin: [["10.0.4.21", "Chrome 131 on macOS"], ["10.0.4.21", "Chrome 131 on macOS"], ["192.168.1.14", "Firefox 133 on Windows"]],
  bob: [["10.0.2.77", "Safari 18 on iOS"], ["10.0.2.77", "Chrome 131 on Windows"]],
};

// ── domain helpers ────────────────────────────────────────────────────────────
const BAND = { INFO: "info", WARNING: "warning", ALERT: "high", CRITICAL: "high" };
const scopedLogs = (me) =>
  users[me].role === "admin" ? logs : logs.filter((l) => l.username === me || l.action.includes(me));

function daily(me, days) {
  const out = [];
  for (let i = days - 1; i >= 0; i--) {
    const d = stamp(new Date(Date.now() - i * 86400000)).slice(0, 10);
    out.push({ date: d, info: 0, warning: 0, high: 0 });
  }
  const index = Object.fromEntries(out.map((r, i) => [r.date, i]));
  for (const l of scopedLogs(me)) {
    const i = index[l.timestamp.slice(0, 10)];
    if (i !== undefined) out[i][BAND[l.severity]]++;
  }
  return out;
}

const publicUser = (name) => ({
  username: name, role: users[name].role, status: users[name].status,
  freeze_reason: users[name].reason, unfreeze_requested: users[name].requested,
});

const toMessage = (m, me) => ({
  id: m.id, sender: m.sender, receiver: m.receiver, outgoing: m.sender === me,
  text: m.decrypted && m.receiver === me ? m.text : null,
  ciphertext_preview: m.encrypted.slice(0, 64), timestamp: m.timestamp, status: m.status, read_at: m.read_at,
});

function checkPin(me, pin, context) {
  const real = users[me].pin;
  if (pin === real) return "ok";
  if (pin === [...real].reverse().join("") && pin !== real) {
    log(me, `[DURESS ALERT] User entered reversed PIN during: ${context}`, "CRITICAL");
    users[me].status = "frozen";
    users[me].reason = "Duress PIN entered — possible coercion";
    return "duress";
  }
  return "wrong";
}

function networkResult() {
  seed = 99;
  const points = [];
  for (let i = 0; i < 950; i++) points.push({ x: Math.abs(100 + gauss() * 25), y: Math.abs(100 + gauss() * 25), suspicious: false });
  const rows = [];
  for (let i = 0; i < 50; i++) {
    const row = Array.from({ length: 13 }, () => +Math.abs(400 + gauss() * 120).toFixed(3));
    rows.push(row);
    points.push({ x: row[3], y: row[4], suspicious: true });
  }
  return {
    summary: { total: 1000, suspicious: 50, normal: 950 },
    features: FEATURES,
    axes: { x: "Flow Bytes/s", y: "Flow Packets/s" },
    points,
    suspicious_rows: { columns: FEATURES, rows },
  };
}
const FEATURES = [
  "Flow Duration", "Total Fwd Packets", "Total Backward Packets", "Flow Bytes/s", "Flow Packets/s",
  "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count", "Packet Length Mean",
  "Packet Length Std", "Idle Mean", "Active Mean",
];

// ── routes ────────────────────────────────────────────────────────────────────
const routes = [];
const on = (method, pattern, handler, opts = {}) => routes.push({ method, pattern, handler, ...opts });

on("POST", /^\/api\/auth\/login$/, ({ body }) => {
  const u = users[body.username?.trim()];
  if (!u || u.password !== body.password) {
    log(body.username || "unknown", "Failed login attempt", "WARNING");
    throw new HttpError(401, "Invalid username or password");
  }
  const name = body.username.trim();
  (devices[name] ||= []).unshift(["127.0.0.1", navigator.userAgent.slice(0, 80)]);
  log(name, "Logged in from 127.0.0.1");
  return { token: `demo.${name}`, user: publicUser(name) };
}, { public: true });

on("POST", /^\/api\/auth\/register$/, ({ body }) => {
  const name = body.username?.trim();
  if (!name) throw new HttpError(422, "Username is required.");
  if (name.toLowerCase() === "admin") throw new HttpError(422, "That username is reserved. Please choose a different username.");
  if (!/^\d{4}$/.test(body.pin)) throw new HttpError(422, "PIN must be exactly 4 digits.");
  if (users[name]) throw new HttpError(409, "Username already exists. Please choose another.");
  users[name] = { role: "client", password: body.password, pin: body.pin, status: "active", reason: "", requested: false };
  log(name, "Registered new client account");
  return { ok: true };
}, { public: true });

on("GET", /^\/api\/auth\/me$/, ({ me }) => publicUser(me), { allowFrozen: true });
on("POST", /^\/api\/auth\/unfreeze-request$/, ({ me }) => {
  users[me].requested = true;
  log(me, "Requested account unfreeze");
  return { ok: true };
}, { allowFrozen: true });

on("GET", /^\/api\/users$/, ({ me }) => Object.keys(users).filter((u) => u !== me));

on("GET", /^\/api\/dashboard$/, ({ me }) => {
  const mine = scopedLogs(me);
  return {
    kpis: {
      sent: messages.filter((m) => m.sender === me).length,
      received: messages.filter((m) => m.receiver === me).length,
      unread: messages.filter((m) => m.receiver === me && m.status !== "read").length,
      tamper_alerts: mine.filter((l) => /Tampering detected|hash mismatch/.test(l.action)).length,
      failed_decryptions: logs.filter((l) => l.username === me && l.action.includes("Failed decryption")).length,
      files_flagged: files.filter((f) => (f.sender === me || f.receiver === me) && f.status !== "safe").length,
    },
    events: daily(me, 14),
    recent_alerts: mine.filter((l) => l.severity !== "INFO").slice(-8).reverse(),
    broadcast,
  };
});

on("GET", /^\/api\/messages\/conversation\/(.+)$/, ({ me, match }) => {
  const other = decodeURIComponent(match[1]);
  return messages
    .filter((m) => (m.sender === me && m.receiver === other) || (m.sender === other && m.receiver === me))
    .map((m) => toMessage(m, me));
});

on("POST", /^\/api\/messages$/, ({ me, body }) => {
  const text = body.message?.trim();
  if (!text) throw new HttpError(422, "Message cannot be empty.");
  if (!users[body.receiver] || body.receiver === me) throw new HttpError(404, "Receiver not found.");
  messages.push({ id: nextId++, sender: me, receiver: body.receiver, text, encrypted: cipher(), decrypted: false, timestamp: now(), status: "sent", read_at: null });
  log(me, `Sent message/file to ${body.receiver}`);
  return { id: nextId - 1 };
});

on("GET", /^\/api\/messages\/inbox$/, ({ me }) => {
  for (const m of messages) if (m.receiver === me && m.status === "sent") m.status = "delivered";
  return messages.filter((m) => m.receiver === me).reverse().map((m) => toMessage(m, me));
});

on("POST", /^\/api\/messages\/(\d+)\/decrypt$/, async ({ me, body, match }) => {
  const m = messages.find((x) => x.id === +match[1] && x.receiver === me);
  if (!m) throw new HttpError(404, "Message not found.");
  if (checkPin(me, body.pin, `decrypt message ${m.id}`) === "wrong") {
    log(me, `Incorrect PIN attempt for message ${m.id}`, "WARNING");
    throw new HttpError(403, "Incorrect PIN. Access denied.");
  }
  const hash = await sha256(m.text);
  Object.assign(m, { decrypted: true, status: "read", read_at: now() });
  log(me, `Decrypted and verified message ${m.id} from ${m.sender}`);
  return { verdict: "verified", message: m.text, sender_hash: hash, receiver_hash: hash };
});

const fileRow = (f, direction) => ({
  id: f.id, direction, counterpart: direction === "sent" ? f.receiver : f.sender, name: f.name,
  original_hash: f.hash, last_checked_hash: f.status === "safe" ? f.hash : "mismatch", status: f.status,
  uploaded_at: f.uploaded, last_checked_at: f.checked,
});

on("GET", /^\/api\/files$/, ({ me }) => ({
  received: files.filter((f) => f.receiver === me).reverse().map((f) => fileRow(f, "received")),
  sent: files.filter((f) => f.sender === me).reverse().map((f) => fileRow(f, "sent")),
}));

on("POST", /^\/api\/files$/, async ({ me, form }) => {
  const file = form.get("file");
  if (checkPin(me, form.get("pin"), `send file ${file.name}`) === "wrong") {
    log(me, `Wrong PIN on file send: ${file.name}`, "WARNING");
    throw new HttpError(403, "Incorrect PIN. File not sent.");
  }
  const receiver = form.get("receiver");
  const content = await file.text();
  const f = { id: files.length + 1, sender: me, receiver, name: file.name, status: "safe", uploaded: now(), checked: now(), content, hash: await sha256(content) };
  files.push(f);
  log(me, `Sent encrypted file '${file.name}' to ${receiver}`);
  return { ok: true, sha256: f.hash };
});

on("POST", /^\/api\/files\/(\d+)\/decrypt$/, ({ me, body, match }) => {
  const f = files.find((x) => x.id === +match[1] && x.receiver === me);
  if (!f) throw new HttpError(404, "File not found.");
  if (checkPin(me, body.pin, `decrypt file ${f.name}`) === "wrong") {
    log(me, `Wrong PIN attempt for file: ${f.name}`, "WARNING");
    throw new HttpError(403, "Incorrect PIN. File access denied.");
  }
  f.checked = now();
  if (f.status !== "safe") {
    log(me, `Tampering detected on file ${f.name}: hash mismatch`, "ALERT");
    throw new HttpError(409, "Integrity check failed: the file's hash has changed.");
  }
  log(me, `Successfully decrypted & downloaded: ${f.name}`);
  return new Response(f.content, {
    headers: { "Content-Type": "application/octet-stream", "Content-Disposition": `attachment; filename="${f.name}"` },
  });
});

on("GET", /^\/api\/security\/overview$/, ({ me }) => {
  const mine = scopedLogs(me);
  const count = (re) => mine.filter((l) => re.test(l.action)).length;
  const tally = (arr, key) => arr.reduce((acc, x) => ((acc[x[key]] = (acc[x[key]] || 0) + 1), acc), {});
  return {
    message_status: tally(messages.filter((m) => m.sender === me || m.receiver === me), "status"),
    severity: tally(mine, "severity"),
    signals: {
      failed_logins: count(/Failed login attempt/),
      failed_decryptions: count(/Failed decryption/),
      wrong_pins: count(/PIN/),
      tamper_events: count(/Tampering detected/),
      duress_alerts: count(/DURESS ALERT/),
    },
    files: tally(files.filter((f) => f.sender === me || f.receiver === me), "status"),
    events: daily(me, 30),
  };
});

function filteredLogs(me, params) {
  const sev = params.get("severity");
  const q = (params.get("q") || "").toLowerCase();
  return scopedLogs(me)
    .filter((l) => (!sev || l.severity === sev) && (!q || l.action.toLowerCase().includes(q) || l.username.toLowerCase().includes(q)))
    .slice()
    .reverse()
    .slice(0, 500);
}
on("GET", /^\/api\/logs$/, ({ me, params }) => filteredLogs(me, params));
on("GET", /^\/api\/logs\/export\.csv$/, ({ me, params }) => {
  const rows = filteredLogs(me, params).map((l) => [l.timestamp, l.username, l.severity, `"${l.action}"`].join(","));
  return new Response(["timestamp,username,severity,action", ...rows].join("\n"), {
    headers: { "Content-Type": "text/csv", "Content-Disposition": 'attachment; filename="audit-logs.csv"' },
  });
});

on("POST", /^\/api\/network\/analyze$/, ({ me }) => {
  log(me, "Ran network anomaly detection on cicids2017-sample.csv (1000 flows)");
  return networkResult();
}, { admin: true, delay: 900 });

on("GET", /^\/api\/admin\/users$/, () =>
  Object.entries(users).map(([username, u]) => ({
    username, role: u.role, status: u.status, unfreeze_requested: u.requested, freeze_reason: u.reason,
    risk_events: logs.filter((l) => l.username === username && l.severity !== "INFO").length,
    last_login: [...logs].reverse().find((l) => l.username === username && l.action.startsWith("Logged in"))?.timestamp || null,
  })), { admin: true });

on("POST", /^\/api\/admin\/users\/(.+)\/freeze$/, ({ me, body, match }) => {
  const name = decodeURIComponent(match[1]);
  if (name === me) throw new HttpError(422, "You cannot freeze your own account.");
  Object.assign(users[name], { status: "frozen", reason: body.reason, requested: false });
  log(me, `Froze account ${name}: ${body.reason}`, "WARNING");
  return { ok: true };
}, { admin: true });

on("POST", /^\/api\/admin\/users\/(.+)\/unfreeze$/, ({ me, match }) => {
  const name = decodeURIComponent(match[1]);
  Object.assign(users[name], { status: "active", reason: "", requested: false });
  log(me, `Unfroze account ${name}`);
  return { ok: true };
}, { admin: true });

on("POST", /^\/api\/admin\/broadcast$/, ({ me, body }) => {
  if (!body.message?.trim()) throw new HttpError(422, "Broadcast message cannot be empty.");
  broadcast = { admin: me, message: body.message.trim(), timestamp: now() };
  log(me, "Sent admin broadcast");
  return { ok: true };
}, { admin: true });

on("GET", /^\/api\/admin\/system$/, () => ({
  users: Object.keys(users).length, messages: messages.length, log_entries: logs.length, files: files.length,
  db_bytes: 90112 + logs.length * 96, uploads_bytes: 48213, disk_used_pct: 41.7, python: "3.11.9", os: "Linux 6.8",
}), { admin: true });

on("GET", /^\/api\/profile$/, ({ me }) => {
  const count = (re) => logs.filter((l) => l.username === me && re.test(l.action)).length;
  const breakdown = {
    failed_logins: count(/Failed login attempt/),
    failed_decryptions: count(/Failed decryption/),
    tamper_events: scopedLogs(me).filter((l) => /Tampering detected/.test(l.action)).length,
  };
  return {
    username: me, role: users[me].role,
    risk_score: breakdown.failed_logins * 2 + breakdown.failed_decryptions * 3 + breakdown.tamper_events * 5,
    risk_breakdown: breakdown,
    devices: (devices[me] || []).slice(0, 20).map(([ip, agent], i) => ({ ip, agent, timestamp: ago(i * 1300 + 3) })),
  };
});

on("POST", /^\/api\/profile\/password$/, ({ me, body }) => {
  if (users[me].password !== body.current_password) throw new HttpError(422, "Current password is incorrect.");
  if (body.new_password.length < 8) throw new HttpError(422, "New password too weak.");
  users[me].password = body.new_password;
  log(me, "Changed account password");
  return { ok: true };
});

// ── fetch interception ────────────────────────────────────────────────────────
const json = (status, data) => new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json" } });

export function installMockApi() {
  const realFetch = window.fetch.bind(window);
  window.fetch = async (input, init = {}) => {
    const url = new URL(typeof input === "string" ? input : input.url, location.href);
    if (!url.pathname.startsWith("/api/") && !url.pathname.includes("/api/")) return realFetch(input, init);
    const path = url.pathname.slice(url.pathname.indexOf("/api/"));
    const method = (init.method || "GET").toUpperCase();
    const route = routes.find((r) => r.method === method && r.pattern.test(path));
    await new Promise((r) => setTimeout(r, route?.delay ?? 220));
    if (!route) return json(404, { detail: "Not found" });

    const auth = (init.headers?.Authorization || "").replace("Bearer demo.", "");
    const me = users[auth] ? auth : null;
    try {
      if (!route.public) {
        if (!me) throw new HttpError(401, "Not authenticated");
        if (!route.allowFrozen && users[me].status === "frozen") throw new HttpError(423, "Account is frozen");
        if (route.admin && users[me].role !== "admin") throw new HttpError(403, "Administrator access required");
      }
      const isForm = init.body instanceof FormData;
      const result = await route.handler({
        me, match: path.match(route.pattern), params: url.searchParams,
        body: !isForm && init.body ? JSON.parse(init.body) : {}, form: isForm ? init.body : null,
      });
      return result instanceof Response ? result : json(200, result);
    } catch (e) {
      if (e instanceof HttpError) return json(e.status, { detail: e.message });
      throw e;
    }
  };
}
