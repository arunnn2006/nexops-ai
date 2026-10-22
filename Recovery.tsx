import { useState } from "react";
import { api, ApiError } from "../api";
import { useAuth } from "../auth";
import { Badge, Banner, StateView, fmtTime, useAsync } from "../components/ui";
import type { RecoveryRequest } from "../types";

export const phraseFor = (r: RecoveryRequest) => `${r.action} ${r.service_name}`;

function ExecuteBox({ r, onDone }: { r: RecoveryRequest; onDone: (msg: string, ok: boolean) => void }) {
  const [typed, setTyped] = useState("");
  const [busy, setBusy] = useState(false);
  async function run() {
    setBusy(true);
    try {
      const res = await api.execute(r.id, typed);
      onDone(`Simulated ${res.action} on ${res.service_name}: ${res.status}.`, res.status === "executed");
    } catch (e) { onDone(e instanceof ApiError ? e.message : "Execution failed", false); }
    finally { setBusy(false); }
  }
  return (
    <div>
      <label className="muted">Type <code>{phraseFor(r)}</code> to confirm (simulated)
        <input aria-label={`Confirmation for request ${r.id}`} value={typed} onChange={(e) => setTyped(e.target.value)} /></label>
      <button className="danger" disabled={busy || typed !== phraseFor(r)} onClick={run}>Execute (simulated)</button>
    </div>
  );
}

export function RecoveryPage() {
  const { hasRole, user } = useAuth();
  const { data, loading, error, reload } = useAsync(() => api.recoveryRequests(), []);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);

  async function decide(r: RecoveryRequest, d: "approve" | "reject") {
    try { await api.decide(r.id, d, ""); setMsg({ ok: true, text: `Request #${r.id} ${d === "approve" ? "approved" : "rejected"}.` }); }
    catch (e) { setMsg({ ok: false, text: e instanceof ApiError ? e.message : "Decision failed" }); }
    reload();
  }
  return (
    <>
      <h1>Recovery approvals</h1>
      <Banner tone="warn"><strong>SIMULATED MODE.</strong> Approved actions change simulated state inside NexOps only. No real service, container or host is touched.</Banner>
      {msg && <Banner tone={msg.ok ? "ok" : "error"}>{msg.text}</Banner>}
      <StateView loading={loading} error={error} onRetry={reload} empty={!data?.length} emptyText="No recovery requests yet. Request one from an incident.">
        {(data ?? []).map((r) => (
          <div className="panel" key={r.id}>
            <div className="row"><strong>#{r.id} {r.action}</strong> on {r.service_name} <Badge value={r.status} /><span className="muted">mode: {r.mode}</span></div>
            <p className="muted">Requested by {r.requested_by_email} {fmtTime(r.created_at)}{r.reason ? ` — “${r.reason}”` : ""}
              {r.decided_by_email ? ` · decided by ${r.decided_by_email}` : ""}</p>
            {r.status === "pending" && (hasRole("admin")
              ? <div className="row"><button onClick={() => decide(r, "approve")}>Approve</button>
                  <button className="secondary" onClick={() => decide(r, "reject")}>Reject</button>
                  {r.requested_by_email === user?.email && <span className="muted">You requested this; the server may refuse self-approval.</span>}</div>
              : <p className="muted">Waiting for an admin to approve or reject.</p>)}
            {r.status === "approved" && hasRole("operator") && (
              <ExecuteBox r={r} onDone={(text, ok) => { setMsg({ ok, text }); reload(); }} />
            )}
            {r.result && <pre>{JSON.stringify({ result: r.result, verification: r.verification }, null, 2)}</pre>}
          </div>
        ))}
      </StateView>
    </>
  );
}
