export interface Series { label: string; color: string; values: number[] }

export function LineChart({ title, labels, series, unit = "" }: { title: string; labels: string[]; series: Series[]; unit?: string }) {
  const W = 520, H = 160, P = 28;
  const all = series.flatMap((s) => s.values);
  if (all.length === 0) return <div className="state">No data points.</div>;
  const min = Math.min(0, ...all), max = Math.max(...all) || 1;
  const n = Math.max(...series.map((s) => s.values.length));
  const x = (i: number) => P + (n <= 1 ? 0 : (i / (n - 1)) * (W - 2 * P));
  const y = (v: number) => H - P - ((v - min) / (max - min || 1)) * (H - 2 * P);
  return (
    <figure className="chart">
      <figcaption>{title}</figcaption>
      <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label={`${title}: ${series.map((s) => s.label).join(", ")}`}>
        <line x1={P} y1={H - P} x2={W - P} y2={H - P} className="axis" />
        <line x1={P} y1={P} x2={P} y2={H - P} className="axis" />
        <text x={4} y={P + 4} className="tick">{max.toFixed(max < 10 ? 2 : 0)}{unit}</text>
        <text x={4} y={H - P} className="tick">{min.toFixed(0)}{unit}</text>
        {labels.length > 1 && <text x={P} y={H - 8} className="tick">{labels[0]}</text>}
        {labels.length > 1 && <text x={W - P} y={H - 8} className="tick" textAnchor="end">{labels[labels.length - 1]}</text>}
        {series.map((s) => (
          <polyline key={s.label} fill="none" stroke={s.color} strokeWidth={2} data-testid="line"
            points={s.values.map((v, i) => `${x(i)},${y(v)}`).join(" ")} />
        ))}
      </svg>
    </figure>
  );
}

export function BarChart({ title, data }: { title: string; data: { label: string; value: number; color: string }[] }) {
  const max = Math.max(1, ...data.map((d) => d.value));
  return (
    <figure className="chart">
      <figcaption>{title}</figcaption>
      <div className="bars" role="img" aria-label={`${title}: ${data.map((d) => `${d.label} ${d.value}`).join(", ")}`}>
        {data.map((d) => (
          <div key={d.label} className="bar-row">
            <span className="bar-label">{d.label}</span>
            <span className="bar-track"><span className="bar-fill" style={{ width: `${(d.value / max) * 100}%`, background: d.color }} /></span>
            <span className="bar-value">{d.value}</span>
          </div>
        ))}
      </div>
    </figure>
  );
}
