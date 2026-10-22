import { useState } from "react";
import { api } from "../api";
import { Badge, StateView, fmtTime, useAsync } from "../components/ui";

export function AuditPage() {
  const [action, setAction] = useState("");
  const [outcome, setOutcome] = useState("");
  const { data, loading, error, reload } = useAsync(() => api.audit({ action, outcome, limit: 100 }), [action, outcome]);
  return (
    <>
      <h1>Audit history</h1>
      <div className="filters">
        <select aria-label="Action prefix" value={action} onChange={(e) => setAction(e.target.value)}>
          <option value="">All actions</option>{["recovery", "incident", "user", "service", "deployment"].map((a) => <option key={a}>{a}</option>)}</select>
        <select aria-label="Outcome" value={outcome} onChange={(e) => setOutcome(e.target.value)}>
          <option value="">Any outcome</option>{["success", "denied", "failed"].map((a) => <option key={a}>{a}</option>)}</select>
      </div>
      <StateView loading={loading} error={error} onRetry={reload} empty={!data?.length} emptyText="No audit entries match.">
        <div className="panel tablewrap"><table>
          <thead><tr><th>When</th><th>Actor</th><th>Action</th><th>Target</th><th>Outcome</th><th>Detail</th></tr></thead>
          <tbody>{(data ?? []).map((a) => (
            <tr key={a.id}><td>{fmtTime(a.observed_at)}</td><td>{a.actor_email ?? "—"}</td><td>{a.action}</td>
              <td>{a.target_type}{a.target_id ? ` #${a.target_id}` : ""}</td><td><Badge value={a.outcome} /></td>
              <td><code>{JSON.stringify(a.detail)}</code></td></tr>
          ))}</tbody></table></div>
      </StateView>
    </>
  );
}
