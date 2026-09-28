import { useEffect, useState } from "react";
import { Download, ScrollText, Search } from "lucide-react";
import { api, downloadResponse } from "../lib/api";
import { useAuth } from "../lib/auth";
import { fmtDateTime, useApi } from "../lib/useApi";
import { useToast } from "../lib/toast";
import { Button, Card, EmptyState, ErrorState, PageHead, SeverityBadge, SkeletonRows } from "../components/ui";

export default function Logs() {
  const { isAdmin } = useAuth();
  const [severity, setSeverity] = useState("");
  const [search, setSearch] = useState("");
  const [q, setQ] = useState("");
  const [exporting, setExporting] = useState(false);
  const notify = useToast();

  // Debounce the free-text search so we don't query on every keystroke.
  useEffect(() => {
    const t = setTimeout(() => setQ(search.trim()), 300);
    return () => clearTimeout(t);
  }, [search]);

  const params = new URLSearchParams();
  if (severity) params.set("severity", severity);
  if (q) params.set("q", q);
  const qs = params.toString();
  const { data, error, loading, reload } = useApi(`/api/logs${qs ? `?${qs}` : ""}`);

  const exportCsv = async () => {
    setExporting(true);
    try {
      const saved = await downloadResponse(await api(`/api/logs/export.csv${qs ? `?${qs}` : ""}`, { raw: true }), "audit-logs.csv");
      if (!saved) notify("CSV export works in the full app. Downloads are turned off in this preview.", "info");
    } catch (e) {
      notify(e.message, "error");
    } finally {
      setExporting(false);
    }
  };

  return (
    <>
      <PageHead title="Audit logs" description={isAdmin ? "Every security-relevant action across the organisation." : "Security-relevant actions on your account."}>
        <Button icon={Download} loading={exporting} onClick={exportCsv}>Export CSV</Button>
      </PageHead>

      <Card flush>
        <div className="card-head">
          <div className="input-icon" style={{ flex: "1 1 260px", maxWidth: 380 }}>
            <Search size={16} aria-hidden="true" />
            <label htmlFor="log-search" className="sr-only">Search logs</label>
            <input id="log-search" className="input" placeholder="Search actions or users" value={search} onChange={(e) => setSearch(e.target.value)} />
          </div>
          <label htmlFor="sev" className="sr-only">Severity</label>
          <select id="sev" className="select" style={{ width: 170 }} value={severity} onChange={(e) => setSeverity(e.target.value)}>
            <option value="">All severities</option>
            <option value="INFO">Info</option>
            <option value="WARNING">Warning</option>
            <option value="ALERT">Alert</option>
            <option value="CRITICAL">Critical</option>
          </select>
          <span className="small muted" style={{ marginLeft: "auto" }}>{data ? `${data.length} ${data.length === 500 ? "most recent " : ""}entries` : ""}</span>
        </div>

        {loading && !data ? <SkeletonRows rows={8} /> : error ? <ErrorState error={error} onRetry={reload} /> : !data.length ? (
          <EmptyState icon={ScrollText} title="No matching log entries">Try a different search or severity.</EmptyState>
        ) : (
          <div className="table-wrap" style={{ opacity: loading ? 0.6 : 1, transition: "opacity .15s" }}>
            <table className="table">
              <thead><tr><th>Time</th><th>Severity</th><th>User</th><th>Action</th></tr></thead>
              <tbody>
                {data.map((l) => (
                  <tr key={l.id}>
                    <td className="nowrap small num">{fmtDateTime(l.timestamp)}</td>
                    <td><SeverityBadge severity={l.severity} /></td>
                    <td className="nowrap">{l.username}</td>
                    <td>{l.action}</td>
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
