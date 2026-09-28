import { useState } from "react";
import { Fingerprint, KeyRound, Lock, Network, ShieldCheck, User } from "lucide-react";
import { useAuth } from "../lib/auth";
import { api } from "../lib/api";
import { Alert, Button, Field } from "../components/ui";

const FEATURES = [
  { icon: Lock, title: "Layered encryption", text: "Every message is encrypted twice with AES (Fernet) and can be RSA-2048 signed." },
  { icon: Fingerprint, title: "Tamper detection", text: "SHA-256 fingerprints are re-verified on every message and shared file." },
  { icon: Network, title: "Breach monitoring", text: "Audit trails, login lockout, a duress PIN and ML anomaly detection on traffic." },
];

const PASSWORD_RULES = [
  [/.{8,}/, "8+ characters"],
  [/[A-Z]/, "uppercase"],
  [/[a-z]/, "lowercase"],
  [/\d/, "number"],
  [/[!@#$%^&*(),.?":{}|<>]/, "symbol"],
];

function RegisterForm({ onDone }) {
  const [form, setForm] = useState({ username: "", password: "", personal_key: "", pin: "" });
  const [errors, setErrors] = useState({});
  const [serverError, setServerError] = useState("");
  const [busy, setBusy] = useState(false);
  const set = (k) => (e) => setForm({ ...form, [k]: k === "pin" ? e.target.value.replace(/\D/g, "") : e.target.value });
  const missing = PASSWORD_RULES.filter(([re]) => !re.test(form.password)).map(([, label]) => label);

  const validate = () => {
    const e = {};
    if (!form.username.trim()) e.username = "Choose a username.";
    if (missing.length) e.password = `Add: ${missing.join(", ")}.`;
    if (!form.personal_key) e.personal_key = "Your personal key encrypts messages sent to you.";
    if (!/^\d{4}$/.test(form.pin)) e.pin = "PIN must be exactly 4 digits.";
    setErrors(e);
    return !Object.keys(e).length;
  };

  const submit = async (e) => {
    e.preventDefault();
    setServerError("");
    if (!validate()) return;
    setBusy(true);
    try {
      await api("/api/auth/register", { method: "POST", body: form });
      onDone(form.username);
    } catch (err) {
      setServerError(err.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <form className="stack" onSubmit={submit} noValidate>
      {serverError && <Alert tone="danger">{serverError}</Alert>}
      <Field label="Username" error={errors.username}>
        {(p) => <input {...p} className="input" autoComplete="username" value={form.username} onChange={set("username")} />}
      </Field>
      <Field label="Password" error={errors.password} hint={form.password && !missing.length ? "Strong password." : "8+ characters with upper and lower case, a number and a symbol."}>
        {(p) => <input {...p} type="password" className="input" autoComplete="new-password" value={form.password} onChange={set("password")} />}
      </Field>
      <Field label="Personal encryption key" error={errors.personal_key} hint="Used to encrypt messages addressed to you. Keep it private.">
        {(p) => <input {...p} type="password" className="input" value={form.personal_key} onChange={set("personal_key")} />}
      </Field>
      <Field label="4-digit PIN" error={errors.pin} hint="Needed to decrypt messages and files.">
        {(p) => <input {...p} type="password" inputMode="numeric" maxLength={4} className="input" value={form.pin} onChange={set("pin")} />}
      </Field>
      <Button type="submit" variant="primary" className="btn-block" loading={busy}>Create client account</Button>
    </form>
  );
}

export default function Login() {
  const { login } = useAuth();
  const [mode, setMode] = useState("login");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async (e) => {
    e.preventDefault();
    if (!username || !password) return setError("Enter your username and password.");
    setBusy(true);
    setError("");
    try {
      await login(username, password);
    } catch (err) {
      setError(err.message);
      setBusy(false);
    }
  };

  return (
    <div className="auth">
      <section className="auth-hero">
        <div className="brand" style={{ padding: 0 }}>
          <span className="brand-logo" aria-hidden="true"><ShieldCheck size={18} color="#fff" /></span>
          <span><span className="brand-name">SecureChat</span><br /><span className="brand-tag">Breach Detection Console</span></span>
        </div>
        <div style={{ marginTop: "auto" }}>
          <h1>Secure messaging with <span>built-in breach detection</span></h1>
          <p style={{ marginTop: 14 }}>Encrypt conversations and files, verify their integrity, and monitor your organisation for suspicious activity — from one console.</p>
        </div>
        <div className="features stack" style={{ gap: 18, marginBottom: "auto" }}>
          {FEATURES.map((f) => (
            <div className="feature" key={f.title}>
              <div className="feature-icon" aria-hidden="true"><f.icon size={19} /></div>
              <div><strong>{f.title}</strong><span>{f.text}</span></div>
            </div>
          ))}
        </div>
      </section>

      <section className="auth-panel">
        <div className="auth-card stack" style={{ gap: 22 }}>
          <div>
            <h2>{mode === "login" ? "Sign in" : "Create an account"}</h2>
            <p className="muted" style={{ marginTop: 4 }}>
              {mode === "login" ? "Use your SecureChat credentials to continue." : "New accounts are registered as clients."}
            </p>
          </div>
          <div className="segmented" role="group" aria-label="Choose action" style={{ alignSelf: "flex-start" }}>
            <button aria-pressed={mode === "login"} onClick={() => setMode("login")}>Sign in</button>
            <button aria-pressed={mode === "register"} onClick={() => { setMode("register"); setNotice(""); }}>Register</button>
          </div>

          {mode === "login" ? (
            <form className="stack" onSubmit={submit} noValidate>
              {notice && <Alert tone="success">{notice}</Alert>}
              {error && <Alert tone="danger">{error}</Alert>}
              <Field label="Username">
                {(p) => (
                  <div className="input-icon"><User size={16} aria-hidden="true" />
                    <input {...p} className="input" autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} autoFocus />
                  </div>
                )}
              </Field>
              <Field label="Password">
                {(p) => (
                  <div className="input-icon"><KeyRound size={16} aria-hidden="true" />
                    <input {...p} type="password" className="input" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} />
                  </div>
                )}
              </Field>
              <Button type="submit" variant="primary" className="btn-block" loading={busy}>Sign in</Button>
              <p className="small muted">Five failed attempts lock the account for 30 minutes.</p>
              {import.meta.env.VITE_DEMO === "1" && (
                <div className="card" style={{ padding: 16, boxShadow: "none" }}>
                  <strong className="small">Preview accounts</strong>
                  <p className="small muted" style={{ margin: "4px 0 10px" }}>Everything runs in your browser with simulated data.</p>
                  <div className="row">
                    <Button type="button" size="sm" onClick={() => { setUsername("Admin"); setPassword("Admin@12345"); }}>Administrator</Button>
                    <Button type="button" size="sm" onClick={() => { setUsername("bob"); setPassword("Demo@1234"); }}>Client (bob)</Button>
                  </div>
                  <p className="small muted" style={{ marginTop: 10 }}>PINs: Admin <code>1234</code> · bob <code>7390</code></p>
                </div>
              )}
            </form>
          ) : (
            <RegisterForm onDone={(name) => { setMode("login"); setUsername(name); setNotice("Account created. Sign in to continue."); }} />
          )}
        </div>
      </section>
    </div>
  );
}
