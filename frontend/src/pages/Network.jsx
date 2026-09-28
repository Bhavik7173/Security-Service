import { useRef, useState } from "react";
import { Activity, AlertTriangle, CheckCircle2, FileSpreadsheet, UploadCloud } from "lucide-react";
import { api } from "../lib/api";
import { fmtBytes } from "../lib/useApi";
import { Alert, Button, Card, PageHead, StatTile } from "../components/ui";
import AnomalyScatter from "../charts/AnomalyScatter";

export default function Network() {
  const [file, setFile] = useState(null);
  const [drag, setDrag] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState(null);
  const input = useRef(null);

  const analyze = async () => {
    setBusy(true);
    setError("");
    try {
      const form = new FormData();
      form.append("file", file);
      setResult(await api("/api/network/analyze", { method: "POST", form }));
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  const pct = result ? ((result.summary.suspicious / result.summary.total) * 100).toFixed(1) : 0;

  return (
    <>
      <PageHead title="Network traffic analysis" description="Upload a CIC-IDS2017 flow export; an Isolation Forest model flags the most anomalous 5% of flows." />

      <Card title="Dataset" subtitle="CSV with CIC-IDS2017 flow features (Flow Duration, Flow Bytes/s, flag counts, …)">
        <div className="row" style={{ alignItems: "stretch" }}>
          <div
            className={`dropzone ${drag ? "drag" : ""}`}
            style={{ flex: "1 1 320px" }}
            role="button"
            tabIndex={0}
            onClick={() => input.current.click()}
            onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && input.current.click()}
            onDragOver={(e) => { e.preventDefault(); setDrag(true); }}
            onDragLeave={() => setDrag(false)}
            onDrop={(e) => { e.preventDefault(); setDrag(false); setFile(e.dataTransfer.files[0]); }}
          >
            {file ? <FileSpreadsheet size={26} aria-hidden="true" /> : <UploadCloud size={26} aria-hidden="true" />}
            {file ? <><strong>{file.name}</strong><span className="small">{fmtBytes(file.size)}</span></> : <><strong>Drop a CSV or click to browse</strong><span className="small">Rows with missing or infinite values are dropped automatically</span></>}
            <input ref={input} type="file" accept=".csv,text/csv" hidden onChange={(e) => setFile(e.target.files[0])} />
          </div>
          <div className="stack" style={{ justifyContent: "center", minWidth: 200 }}>
            <Button variant="primary" icon={Activity} loading={busy} disabled={!file} onClick={analyze}>{busy ? "Analysing…" : "Run detection"}</Button>
            {import.meta.env.VITE_DEMO === "1" && !file && (
              <Button icon={FileSpreadsheet} onClick={() => setFile(new File(["Flow Duration,Flow Bytes/s\n"], "cicids2017-sample.csv", { type: "text/csv" }))}>Use sample dataset</Button>
            )}
            <span className="small muted">Model: Isolation Forest · contamination 5%</span>
          </div>
        </div>
        {error && <div className="mt"><Alert tone="danger">{error}</Alert></div>}
      </Card>

      {result && (
        <>
          <div className="grid grid-kpi mt">
            <StatTile icon={Activity} label="Flows analysed" value={result.summary.total.toLocaleString()} />
            <StatTile icon={AlertTriangle} label="Suspicious flows" value={result.summary.suspicious.toLocaleString()} hint={`${pct}% of traffic`} tone="danger" />
            <StatTile icon={CheckCircle2} label="Normal flows" value={result.summary.normal.toLocaleString()} tone="success" />
          </div>

          <Card title="Flow distribution" subtitle={`${result.axes.x} vs ${result.axes.y}${result.points.length < result.summary.total ? " · normal flows sampled" : ""}`} className="mt">
            <AnomalyScatter points={result.points} axes={result.axes} />
          </Card>

          <Card title="Suspicious flows" subtitle={`First ${result.suspicious_rows.rows.length} flagged flows · ${result.features.length} features used`} flush className="mt">
            <div className="table-wrap" style={{ maxHeight: 420, overflowY: "auto" }}>
              <table className="table">
                <thead><tr>{result.suspicious_rows.columns.map((c) => <th key={c} className={c === "Label" ? "" : "num"}>{c}</th>)}</tr></thead>
                <tbody>
                  {result.suspicious_rows.rows.map((r, i) => (
                    <tr key={i}>{r.map((v, j) => <td key={j} className={result.suspicious_rows.columns[j] === "Label" ? "" : "num"}>{v ?? "—"}</td>)}</tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
        </>
      )}
    </>
  );
}
