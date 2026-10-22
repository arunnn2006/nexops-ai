import { useState, type FormEvent } from "react";
import { Link, useParams } from "react-router-dom";
import { api, ApiError } from "../api";
import { useAuth } from "../auth";
import { Badge, Banner, StateView, fmtTime, useAsync } from "../components/ui";
import type { Diagnosis, IncidentDetail } from "../types";

export function DiagnosisView({ dx }: { dx: Diagnosis }) {
  return (
    <div className="panel">
      <h2>Diagnosis <span className="muted">({dx.method}, generated {fmtTime(dx.generated_at)})</span></h2>
      <p className="muted">{dx.summary}</p>
      <h2>Observed facts</h2>
      {dx.facts.map((f, i) => (
        <div className="fact" key={i}><strong>Observed:</strong> {f.text}
          {f.evidence_id !== null && <span className="muted"> (evidence #{f.evidence_id})</span>}</div>
      ))}
      <h2>Hypotheses (not confirmed)</h2>
      {dx.hypotheses.map((h, i) => (
        <div className="hyp" key={i}>
          <strong>Hypothesis</strong> <Badge value={h.confidence} /> <span className="muted">confidence — not a confirmed cause</span>
          <div>{h.statement}</div>
          {h.supporting_evidence_ids.length > 0 && <div className="muted">Supported by evidence: {h.supporting_evidence_ids.map((id) => `#${id}`).join(", ")}</div>}
          {h.missing_evidence.length > 0 && <div className="muted">Would help confirm: {h.missing_evidence.join("; ")}</div>}
        </div>
      ))}
      <h2>Suggested next steps</h2>
      <ul>{dx.next_steps.map((s, i) => <li key={i}>{s}</li>)}</ul>
      <h2>Limitations</h2>
      <ul className="muted">{dx.limitations.map((s, i) => <li key={i}>{s}</li>)}</ul>
    </div>
  );
}

function RecoveryPanel({ inc }: { inc: IncidentDetail }) {
  const { hasRole } = useAuth();
  const actions = useAsync(() => api.recoveryActions(), []);
  const [action, setAction] = useState("restart_service");
  const [reason, setReason] = useState("");
  const [msg, setMsg] = useState<{ tone: "ok" | "error"; text: string } | null>(null);
  if (inc.service_id === null) return null;
  if (!hasRole("operator")) return <div className="panel"><h2>Recovery</h2><p className="muted">Requesting recovery requires the operator role.</p></div>;

  async function submit(e: FormEvent) {
    e.preventDefault();
    try {
      await api.createRecovery({ service_id: inc.service_id!, action, incident_id: inc.id, reason });
      setMsg({ tone: "ok", text: "Request submitted. An admin must approve it on the Recovery page before it can run (simulated)." });
    } catch (err) { setMsg({ tone: "error", text: err instanceof ApiError ? err.message : "Request failed" }); }
  }
  return (
    <div className="panel">
      <h2>Request recovery (simulated)</h2>
      <p className="muted">Only allowlisted actions on disposable demo services. Nothing real is restarted or changed.</p>
      <form onSubmit={submit} className="row">
        <select aria-label="Recovery action" value={action} onChange={(e) => setAction(e.target.value)}>
          {(actions.data ?? []).map((a) => <option key={a.name} value={a.name}>{a.name}</option>)}
        </select>
        <input aria-label="Reason" placeholder="Reason (optional)" value={reason} onChange={(e) => setReason(e.target.value)} maxLength={500} />
        <button type="submit">Submit request</button>
      </form>
      {actions.data && <p className="muted">{actions.data.find((a) => a.name === action)?.simulated_effect}</p>}
      {msg && <Banner tone={msg.tone}>{msg.text}</Banner>}
    </div>
  );
}

export function IncidentDetailPage() {
  const id = Number(useParams().id);
  const { hasRole } = useAuth();
  const { data, loading, error, reload } = useAsync(() => api.incident(id), [id]);
  const [msg, setMsg] = useState<string | null>(null);

  async function setStatus(status: string) {
    try { await api.setIncidentStatus(id, status); reload(); } catch (e) { setMsg(e instanceof Error ? e.message : "Update failed"); }
  }
  async function rediagnose() {
    try { await api.diagnose(id); reload(); } catch (e) { setMsg(e instanceof Error ? e.message : "Diagnosis failed"); }
  }
  return (
    <>
      <p><Link to="/incidents">← All incidents</Link></p>
      <StateView loading={loading} error={error} onRetry={reload}>
        {data && (
          <>
            <h1>{data.title}</h1>
            <div className="row"><Badge value={data.severity} /><Badge value={data.status} /><span className="muted">rule: {data.rule} · service: {data.service_name ?? "—"} · detected {fmtTime(data.detected_at)}</span></div>
            <p>{data.summary}</p>
            {msg && <Banner tone="error">{msg}</Banner>}
            {hasRole("operator") && (
              <div className="row">
                <label>Status <select aria-label="Incident status" value={data.status} onChange={(e) => setStatus(e.target.value)}>
                  {["open", "investigating", "resolved"].map((s) => <option key={s}>{s}</option>)}</select></label>
                <button className="secondary" onClick={rediagnose}>Regenerate diagnosis</button>
              </div>
            )}
            <div className="panel">
              <h2>Evidence ({data.evidence.length})</h2>
              <div className="tablewrap"><table><thead><tr><th>#</th><th>Kind</th><th>Observed</th><th>Summary</th></tr></thead>
                <tbody>{data.evidence.map((e) => (
                  <tr key={e.id}><td>{e.id}</td><td><Badge value={e.kind} /></td><td>{fmtTime(e.observed_at)}</td>
                    <td>{e.summary}<details><summary className="muted">data</summary><pre>{JSON.stringify(e.data, null, 2)}</pre></details></td></tr>
                ))}</tbody></table></div>
            </div>
            {data.latest_diagnosis ? <DiagnosisView dx={data.latest_diagnosis} /> : <Banner tone="info">No diagnosis generated yet.</Banner>}
            <RecoveryPanel inc={data} />
          </>
        )}
      </StateView>
    </>
  );
}
