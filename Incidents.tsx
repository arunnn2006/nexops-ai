import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api";
import { useAuth } from "../auth";
import { Badge, Banner, StateView, fmtTime, useAsync } from "../components/ui";

const PAGE = 15;
const RULES = ["brute_force", "service_down", "high_error_rate", "high_latency", "suspicious_access", "privilege_change"];

export function IncidentsPage() {
  const nav = useNavigate();
  const { hasRole } = useAuth();
  const [f, setF] = useState({ status: "", severity: "", rule: "", q: "" });
  const [offset, setOffset] = useState(0);
  const [note, setNote] = useState<{ tone: "ok" | "error"; text: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const { data, loading, error, reload } = useAsync(() => api.incidents({ ...f, limit: PAGE, offset }), [f, offset]);
  const set = (k: keyof typeof f, v: string) => { setF({ ...f, [k]: v }); setOffset(0); };

  async function detect() {
    setBusy(true); setNote(null);
    try { const r = await api.detect(); setNote({ tone: "ok", text: `Detection finished: ${r.created} new incident(s).` }); reload(); }
    catch (e) { setNote({ tone: "error", text: e instanceof Error ? e.message : "Detection failed" }); }
    finally { setBusy(false); }
  }
  return (
    <>
      <div className="row"><h1 style={{ marginRight: "auto" }}>Incidents</h1>
        {hasRole("operator") && <button onClick={detect} disabled={busy}>{busy ? "Running…" : "Run detection now"}</button>}</div>
      {note && <Banner tone={note.tone}>{note.text}</Banner>}
      <div className="filters">
        <input placeholder="Search title or summary" aria-label="Search" value={f.q} onChange={(e) => set("q", e.target.value)} />
        <select aria-label="Status" value={f.status} onChange={(e) => set("status", e.target.value)}>
          <option value="">Any status</option>{["open", "investigating", "resolved"].map((s) => <option key={s}>{s}</option>)}</select>
        <select aria-label="Severity" value={f.severity} onChange={(e) => set("severity", e.target.value)}>
          <option value="">Any severity</option>{["critical", "high", "medium", "low"].map((s) => <option key={s}>{s}</option>)}</select>
        <select aria-label="Rule" value={f.rule} onChange={(e) => set("rule", e.target.value)}>
          <option value="">Any rule</option>{RULES.map((s) => <option key={s}>{s}</option>)}</select>
      </div>
      <StateView loading={loading} error={error} onRetry={reload} empty={!data?.items.length}
        emptyText="No incidents match. Run detection or adjust the filters.">
        <div className="panel tablewrap"><table>
          <thead><tr><th>Severity</th><th>Title</th><th>Rule</th><th>Service</th><th>Status</th><th>Detected</th></tr></thead>
          <tbody>{(data?.items ?? []).map((i) => (
            <tr key={i.id} className="click" tabIndex={0} onClick={() => nav(`/incidents/${i.id}`)}
              onKeyDown={(e) => e.key === "Enter" && nav(`/incidents/${i.id}`)}>
              <td><Badge value={i.severity} /></td><td>{i.title}</td><td>{i.rule}</td><td>{i.service_name ?? "—"}</td>
              <td><Badge value={i.status} /></td><td>{fmtTime(i.detected_at)}</td></tr>
          ))}</tbody></table></div>
        <div className="row">
          <button className="secondary" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))}>Previous</button>
          <span className="muted">{offset + 1}–{Math.min(offset + PAGE, data?.total ?? 0)} of {data?.total ?? 0}</span>
          <button className="secondary" disabled={offset + PAGE >= (data?.total ?? 0)} onClick={() => setOffset(offset + PAGE)}>Next</button>
        </div>
      </StateView>
    </>
  );
}
