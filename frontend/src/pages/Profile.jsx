import { useState } from "react";
import { Gauge, KeyRound, Laptop } from "lucide-react";
import { api } from "../lib/api";
import { fmtDateTime, useApi } from "../lib/useApi";
import { useToast } from "../lib/toast";
import { Alert, Button, Card, EmptyState, ErrorState, Field, PageHead, SkeletonRows } from "../components/ui";

function riskLevel(score) {
  if (score >= 20) return { label: "High", tone: "danger" };
  if (score >= 8) return { label: "Elevated", tone: "warning" };
  return { label: "Low", tone: "success" };
}

function PasswordForm() {
  const [form, setForm] = useState({ current_password: "", new_password: "", confirm: "" });
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const notify = useToast();
  const set = (k) => (e) => setForm({ ...form, [k]: e.target.value });

  const submit = async (e) => {
    e.preventDefault();
    setError("");
    if (form.new_password !== form.confirm) return setError("New passwords don't match.");
    setBusy(true);
    try {
      await api("/api/profile/password", { method: "POST", body: { current_password: form.current_password, new_password: form.new_password } });
      setForm({ current_password: "", new_password: "", confirm: "" });
      notify("Password updated.");
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <form className="stack" onSubmit={submit}>
      {error && <Alert tone="danger">{error}</Alert>}
      <Field label="Current password">{(p) => <input {...p} type="password" className="input" autoComplete="current-password" value={form.current_password} onChange={set("current_password")} />}</Field>
      <Field label="New password" hint="8+ characters with upper and lower case, a number and a symbol.">{(p) => <input {...p} type="password" className="input" autoComplete="new-password" value={form.new_password} onChange={set("new_password")} />}</Field>
      <Field label="Confirm new password">{(p) => <input {...p} type="password" className="input" autoComplete="new-password" value={form.confirm} onChange={set("confirm")} />}</Field>
      <Button type="submit" variant="primary" icon={KeyRound} loading={busy} disabled={!form.current_password || !form.new_password}>Update password</Button>
    </form>
  );
}

export default function Profile() {
  const { data, error, loading, reload } = useApi("/api/profile");
  if (error) return <Card><ErrorState error={error} onRetry={reload} /></Card>;
  const level = data ? riskLevel(data.risk_score) : null;

  return (
    <>
      <PageHead title="Profile" description="Your account's risk signals, sign-in history and credentials." />
      <div className="grid grid-2">
        <Card title="Suspicious activity score" subtitle="Failed logins × 2 + failed decryptions × 3 + tamper events × 5">
          {loading ? <SkeletonRows /> : (
            <div className="stack">
              <div className="row" style={{ gap: 16 }}>
                <div className={`stat-icon ${level.tone}`} style={{ width: 52, height: 52 }} aria-hidden="true"><Gauge size={24} /></div>
                <div>
                  <div className="stat-value" style={{ fontSize: "2.2rem" }}>{data.risk_score}</div>
                  <span className={`badge badge-${level.tone}`}>{level.label} risk</span>
                </div>
              </div>
              <table className="table">
                <tbody>
                  <tr><td>Failed sign-ins</td><td className="num">{data.risk_breakdown.failed_logins}</td></tr>
                  <tr><td>Failed decryptions</td><td className="num">{data.risk_breakdown.failed_decryptions}</td></tr>
                  <tr><td>Tamper events</td><td className="num">{data.risk_breakdown.tamper_events}</td></tr>
                </tbody>
              </table>
            </div>
          )}
        </Card>
        <Card title="Change password"><PasswordForm /></Card>
      </div>

      <Card title="Sign-in history" subtitle="Last 20 sign-ins" flush className="mt">
        {loading ? <SkeletonRows /> : !data.devices.length ? <EmptyState icon={Laptop} title="No sign-ins recorded" /> : (
          <div className="table-wrap">
            <table className="table">
              <thead><tr><th>Time</th><th>IP address</th><th>Device</th></tr></thead>
              <tbody>
                {data.devices.map((d, i) => (
                  <tr key={i}>
                    <td className="nowrap small num">{fmtDateTime(d.timestamp)}</td>
                    <td className="mono">{d.ip}</td>
                    <td className="small muted" style={{ maxWidth: 520, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={d.agent}>{d.agent}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </>
  );
}
