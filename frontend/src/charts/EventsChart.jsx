import { useState } from "react";
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { AlertTriangle, BarChart3, Info, ShieldAlert, Table2 } from "lucide-react";
import { useChartTheme } from "./theme";
import { fmtDate } from "../lib/useApi";

// Three severity bands (ALERT + CRITICAL merged into "High") — validated for CVD and
// normal-vision separation. Status colours always travel with an icon and a label.
export const BANDS = [
  { key: "info", label: "Info", color: "series-1", icon: Info },
  { key: "warning", label: "Warning", color: "status-warning", icon: AlertTriangle },
  { key: "high", label: "Alert / Critical", color: "status-critical", icon: ShieldAlert },
];

function EventsTooltip({ active, payload, label, colors }) {
  if (!active || !payload?.length) return null;
  const row = payload[0].payload;
  const total = BANDS.reduce((sum, b) => sum + row[b.key], 0);
  return (
    <div className="chart-tooltip">
      <div className="title">{fmtDate(label)} · {total} events</div>
      {[...BANDS].reverse().map((b) => (
        <div className="line" key={b.key}>
          <span className="swatch" style={{ background: colors[b.color] }} />
          <b.icon size={12} aria-hidden="true" />
          {b.label}
          <b>{row[b.key]}</b>
        </div>
      ))}
    </div>
  );
}

export function SeverityLegend({ colors }) {
  return (
    <div className="chart-legend" aria-label="Legend">
      {BANDS.map((b) => (
        <span key={b.key}>
          <span className="swatch" style={{ background: colors[b.color] }} aria-hidden="true" />
          <b.icon size={13} aria-hidden="true" />
          {b.label}
        </span>
      ))}
    </div>
  );
}

export default function EventsChart({ data, height = 260 }) {
  const colors = useChartTheme();
  const [view, setView] = useState("chart");
  const total = data.reduce((s, d) => s + d.info + d.warning + d.high, 0);

  return (
    <div>
      <div className="row" style={{ marginBottom: 14 }}>
        <SeverityLegend colors={colors} />
        <div className="spacer" />
        <div className="segmented" role="group" aria-label="View as">
          <button aria-pressed={view === "chart"} onClick={() => setView("chart")} aria-label="Chart view"><BarChart3 size={15} /></button>
          <button aria-pressed={view === "table"} onClick={() => setView("table")} aria-label="Table view"><Table2 size={15} /></button>
        </div>
      </div>

      {view === "chart" ? (
        <div style={{ height }} role="img" aria-label={`Security events per day, ${total} total, stacked by severity`}>
          <ResponsiveContainer>
            <BarChart data={data} margin={{ top: 4, right: 4, bottom: 0, left: -18 }} barCategoryGap="28%">
              <CartesianGrid vertical={false} stroke={colors.grid} />
              <XAxis dataKey="date" tickFormatter={fmtDate} tickLine={false} axisLine={{ stroke: colors.grid }} minTickGap={16} />
              <YAxis allowDecimals={false} tickLine={false} axisLine={false} />
              <Tooltip content={<EventsTooltip colors={colors} />} cursor={{ fill: colors.grid, opacity: 0.5 }} />
              {BANDS.map((b, i) => (
                <Bar
                  key={b.key}
                  dataKey={b.key}
                  name={b.label}
                  stackId="sev"
                  fill={colors[b.color]}
                  stroke={colors.surface}
                  strokeWidth={2}
                  radius={i === BANDS.length - 1 ? [4, 4, 0, 0] : 0}
                  isAnimationActive={false}
                />
              ))}
            </BarChart>
          </ResponsiveContainer>
        </div>
      ) : (
        <div className="table-wrap" style={{ maxHeight: height, overflowY: "auto" }}>
          <table className="table">
            <thead>
              <tr><th>Date</th>{BANDS.map((b) => <th key={b.key} className="num">{b.label}</th>)}<th className="num">Total</th></tr>
            </thead>
            <tbody>
              {data.map((d) => (
                <tr key={d.date}>
                  <td>{fmtDate(d.date)}</td>
                  {BANDS.map((b) => <td key={b.key} className="num">{d[b.key]}</td>)}
                  <td className="num"><strong>{d.info + d.warning + d.high}</strong></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
