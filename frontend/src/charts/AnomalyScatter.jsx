import { useMemo, useState } from "react";
import { CartesianGrid, ResponsiveContainer, Scatter, ScatterChart, Tooltip, XAxis, YAxis, ZAxis } from "recharts";
import { useChartTheme } from "./theme";

const compact = new Intl.NumberFormat(undefined, { notation: "compact", maximumFractionDigits: 1 });

function PointTooltip({ active, payload, axes }) {
  if (!active || !payload?.length) return null;
  const p = payload[0].payload;
  return (
    <div className="chart-tooltip">
      <div className="title">{p.suspicious ? "Suspicious flow" : "Normal flow"}</div>
      <div className="line">{axes.x}<b>{compact.format(p.x)}</b></div>
      <div className="line">{axes.y}<b>{compact.format(p.y)}</b></div>
    </div>
  );
}

/** Two series only (normal vs suspicious) — validated all-pairs for scatter use. */
export default function AnomalyScatter({ points, axes, height = 340 }) {
  const colors = useChartTheme();
  const [log, setLog] = useState(false);

  const { normal, suspicious, dropped } = useMemo(() => {
    const usable = log ? points.filter((p) => p.x > 0 && p.y > 0) : points;
    return {
      normal: usable.filter((p) => !p.suspicious),
      suspicious: usable.filter((p) => p.suspicious),
      dropped: points.length - usable.length,
    };
  }, [points, log]);

  const scale = log ? "log" : "linear";
  return (
    <div>
      <div className="row" style={{ marginBottom: 12 }}>
        <div className="chart-legend">
          <span><span className="swatch dot" style={{ background: colors["series-1"] }} aria-hidden="true" />Normal ({normal.length})</span>
          <span><span className="swatch" style={{ background: colors["series-2"], transform: "rotate(45deg)" }} aria-hidden="true" />Suspicious ({suspicious.length})</span>
        </div>
        <div className="spacer" />
        <div className="segmented" role="group" aria-label="Axis scale">
          <button aria-pressed={!log} onClick={() => setLog(false)}>Linear</button>
          <button aria-pressed={log} onClick={() => setLog(true)}>Log</button>
        </div>
      </div>
      <div style={{ height }} role="img" aria-label={`Scatter of ${axes.x} against ${axes.y}; ${suspicious.length} suspicious flows highlighted`}>
        <ResponsiveContainer>
          <ScatterChart margin={{ top: 8, right: 12, bottom: 24, left: 8 }}>
            <CartesianGrid stroke={colors.grid} />
            <XAxis type="number" dataKey="x" name={axes.x} scale={scale} domain={["auto", "auto"]} tickFormatter={compact.format}
              tickLine={false} axisLine={{ stroke: colors.grid }}
              label={{ value: axes.x, position: "insideBottom", offset: -14, fill: colors["text-3"], fontSize: 12 }} />
            <YAxis type="number" dataKey="y" name={axes.y} scale={scale} domain={["auto", "auto"]} tickFormatter={compact.format}
              tickLine={false} axisLine={false} width={56}
              label={{ value: axes.y, angle: -90, position: "insideLeft", offset: 4, fill: colors["text-3"], fontSize: 12 }} />
            <ZAxis range={[36, 36]} />
            <Tooltip content={<PointTooltip axes={axes} />} cursor={{ stroke: colors.axis, strokeDasharray: "3 3" }} />
            <Scatter data={normal} fill={colors["series-1"]} fillOpacity={0.55} isAnimationActive={false} />
            {/* Suspicious points differ by shape as well as colour, with a surface ring so they sit above the cloud. */}
            <Scatter data={suspicious} fill={colors["series-2"]} shape="diamond" stroke={colors.surface} strokeWidth={1.5} isAnimationActive={false} />
          </ScatterChart>
        </ResponsiveContainer>
      </div>
      {dropped > 0 && <p className="small muted">{dropped} flows with zero values are hidden on the log scale.</p>}
    </div>
  );
}
