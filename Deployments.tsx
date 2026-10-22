import { useState } from "react";
import { api } from "../api";
import { Badge, Banner, StateView, fmtTime, useAsync } from "../components/ui";

export function DeploymentsPage() {
  const [serviceId, setServiceId] = useState<number | undefined>();
  const services = useAsync(() => api.services(), []);
  const { data, loading, error, reload } = useAsync(() => api.deployments(serviceId), [serviceId]);
  return (
    <>
      <h1>Deployment history</h1>
      <Banner tone="info">NexOps records deployment history; it does not perform deployments. Source “sample” rows are synthetic demo fixtures.</Banner>
      <div className="filters">
        <select aria-label="Filter by service" value={serviceId ?? ""} onChange={(e) => setServiceId(e.target.value ? Number(e.target.value) : undefined)}>
          <option value="">All services</option>
          {(services.data ?? []).map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
        </select>
      </div>
      <StateView loading={loading} error={error} onRetry={reload} empty={!data?.length} emptyText="No deployments match.">
        <div className="panel tablewrap"><table>
          <thead><tr><th>Service</th><th>Version</th><th>Status</th><th>Source</th><th>By</th><th>Commit</th><th>When</th></tr></thead>
          <tbody>{(data ?? []).map((d) => (
            <tr key={d.id}><td>{d.service_name}</td><td>{d.version}</td><td><Badge value={d.status} /></td><td>{d.source}</td>
              <td>{d.deployed_by ?? "—"}</td><td>{d.commit_sha ?? "—"}</td><td>{fmtTime(d.deployed_at)}</td></tr>
          ))}</tbody></table></div>
      </StateView>
    </>
  );
}
