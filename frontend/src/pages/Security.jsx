import { AlertOctagon, FileCheck2, FileWarning, KeyRound, LogIn, ShieldAlert, Unlock } from "lucide-react";
import { useApi } from "../lib/useApi";
import { Card, ErrorState, PageHead, SeverityBadge, SkeletonRows, StatTile } from "../components/ui";
import EventsChart from "../charts/EventsChart";

const SEVERITY_ORDER = ["INFO", "WARNING", "ALERT", "CRITICAL"];
const METER_COLOR = { INFO: "var(--series-1)", WARNING: "var(--status-warning)", ALERT: "var(--status-critical)", CRITICAL: "var(--status-critical)" };

export default function Security() {
  const { data, error, loading, reload } = useApi("/api/security/overview");
  if (error) return <Card><ErrorState error={error} onRetry={reload} /></Card>;
  const s = data?.signals;
  const sevTotal = data ? Object.values(data.severity).reduce((a, b) => a + b, 0) : 0;
  const msgTotal = data ? Object.values(data.message_status).reduce((a, b) => a + b, 0) : 0;

  return (
    <>
      <PageHead title="Security center" description="Breach indicators, audit severity and integrity status over the last 30 days." />

      <div className="grid grid-kpi">
        <StatTile icon={LogIn} label="Failed logins" value={s?.failed_logins} tone={s?.failed_logins ? "warning" : ""} loading={loading} />
        <StatTile icon={KeyRound} label="PIN events" value={s?.wrong_pins} hint="Wrong or duress PIN entries" loading={loading} />
        <StatTile icon={Unlock} label="Failed decryptions" value={s?.failed_decryptions} tone={s?.failed_decryptions ? "warning" : ""} loading={loading} />
        <StatTile icon={ShieldAlert} label="Tamper events" value={s?.tamper_events} tone={s?.tamper_events ? "danger" : "success"} loading={loading} />
        <StatTile icon={AlertOctagon} label="Duress alerts" value={s?.duress_alerts} tone={s?.duress_alerts ? "danger" : "success"} loading={loading} />
      </div>

      <Card title="Event trend" subtitle="Daily audit events by severity, last 30 days" className="mt">
        {loading ? <SkeletonRows rows={6} /> : <EventsChart data={data.events} height={280} />}
      </Card>

      <div className="grid grid-2 mt">
        <Card title="Severity breakdown" subtitle={loading ? "" : `${sevTotal} audit events in scope`}>
          {loading ? <SkeletonRows /> : SEVERITY_ORDER.map((sev) => {
            const n = data.severity[sev] || 0;
            return (
              <div className="meter" key={sev}>
                <SeverityBadge severity={sev} />
                <div className="meter-track" aria-hidden="true">
                  <div className="meter-fill" style={{ width: `${sevTotal ? (n / sevTotal) * 100 : 0}%`, background: METER_COLOR[sev] }} />
                </div>
                <span className="num" style={{ textAlign: "right", fontWeight: 650 }}>{n}</span>
              </div>
            );
          })}
        </Card>

        <Card title="Integrity status" subtitle="Messages and files you are party to">
          {loading ? <SkeletonRows /> : (
            <div className="stack">
              <div className="row">
                <span className="muted small" style={{ width: 110 }}>Messages</span>
                {["sent", "delivered", "read"].map((k) => (
                  <span key={k} className="badge badge-neutral">{k[0].toUpperCase() + k.slice(1)}: <strong className="num">{data.message_status[k] || 0}</strong></span>
                ))}
                <span className="small muted">({msgTotal} total)</span>
              </div>
              <div className="row">
                <span className="muted small" style={{ width: 110 }}>Files</span>
                <span className="badge badge-success"><FileCheck2 size={12} aria-hidden="true" />Verified: <strong className="num">{data.files.safe || 0}</strong></span>
                <span className="badge badge-danger"><FileWarning size={12} aria-hidden="true" />Tampered: <strong className="num">{data.files.tampered || 0}</strong></span>
              </div>
              <p className="small muted">Files are re-hashed with SHA-256 each time they are decrypted; any difference from the upload-time hash marks the file as tampered and raises an ALERT.</p>
            </div>
          )}
        </Card>
      </div>
    </>
  );
}
