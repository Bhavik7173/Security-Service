import { Link } from "react-router-dom";
import { ArrowRight, FileWarning, Inbox, Send, ShieldAlert, ShieldCheck, Unlock } from "lucide-react";
import { useAuth } from "../lib/auth";
import { fmtDateTime, useApi } from "../lib/useApi";
import { Alert, Card, EmptyState, ErrorState, PageHead, SeverityBadge, SkeletonRows, StatTile } from "../components/ui";
import EventsChart from "../charts/EventsChart";

export default function Dashboard() {
  const { user, isAdmin } = useAuth();
  const { data, error, loading, reload } = useApi("/api/dashboard");
  const k = data?.kpis;

  if (error) return <Card><ErrorState error={error} onRetry={reload} /></Card>;

  const threats = k ? k.tamper_alerts + k.files_flagged : 0;
  return (
    <>
      <PageHead
        title={`Welcome back, ${user.username}`}
        description={isAdmin ? "Organisation-wide security posture for the last 14 days." : "Your messages, files and security activity at a glance."}
      >
        <Link to="/messages" className="btn btn-primary"><Send size={16} aria-hidden="true" />New secure message</Link>
      </PageHead>

      {data?.broadcast && (
        <div className="mt" style={{ marginBottom: 16 }}>
          <Alert tone="warning" title={`Broadcast from ${data.broadcast.admin} · ${fmtDateTime(data.broadcast.timestamp)}`}>
            {data.broadcast.message}
          </Alert>
        </div>
      )}

      <div className="grid grid-kpi">
        <StatTile icon={Send} label="Messages sent" value={k?.sent} loading={loading} />
        <StatTile icon={Inbox} label="Messages received" value={k?.received} hint={k ? `${k.unread} awaiting decryption` : null} loading={loading} />
        <StatTile icon={ShieldAlert} label="Tamper alerts" value={k?.tamper_alerts} tone={k?.tamper_alerts ? "danger" : "success"} loading={loading} />
        <StatTile icon={Unlock} label="Failed decryptions" value={k?.failed_decryptions} tone={k?.failed_decryptions ? "warning" : ""} loading={loading} />
        <StatTile icon={FileWarning} label="Files flagged" value={k?.files_flagged} tone={k?.files_flagged ? "danger" : "success"} loading={loading} />
      </div>

      <div className="grid grid-main mt">
        <Card title="Security events" subtitle="Daily audit events by severity, last 14 days">
          {loading ? <SkeletonRows rows={6} /> : <EventsChart data={data.events} />}
        </Card>

        <Card
          title="Recent alerts"
          subtitle="Warnings and above"
          flush
          actions={<Link to="/logs" className="btn btn-ghost btn-sm">View all <ArrowRight size={14} aria-hidden="true" /></Link>}
        >
          {loading ? (
            <SkeletonRows />
          ) : data.recent_alerts.length ? (
            <ul className="list">
              {data.recent_alerts.map((a, i) => (
                <li key={i} className="list-item">
                  <SeverityBadge severity={a.severity} />
                  <div style={{ minWidth: 0 }}>
                    <div className="small" style={{ fontWeight: 600 }}>{a.action}</div>
                    <div className="meta">{a.username} · {fmtDateTime(a.timestamp)}</div>
                  </div>
                </li>
              ))}
            </ul>
          ) : (
            <EmptyState icon={ShieldCheck} title="No alerts">Nothing above informational level.</EmptyState>
          )}
        </Card>
      </div>

      {!loading && threats === 0 && (
        <div className="mt">
          <Alert tone="success" title="No integrity threats detected">All messages and files you can access passed their last SHA-256 verification.</Alert>
        </div>
      )}
    </>
  );
}
