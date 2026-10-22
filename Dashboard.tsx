import { Link } from "react-router-dom";
import { api } from "../api";
import { BarChart } from "../components/charts";
import { Badge, StateView, fmtTime, useAsync } from "../components/ui";

const SEV_COLOR: Record<string, string> = { low: "#f5a524", medium: "#f5a524", high: "#f5594e", critical: "#c026d3" };

export function DashboardPage() {
  const { data, loading, error, reload } = useAsync(() => api.dashboard(), []);
  return (
    <>
      <h1>Operations overview</h1>
      <StateView loading={loading} error={error} onRetry={reload}>
        {data && (
          <>
            <div className="cards">
              {Object.entries(data.services_by_status).map(([k, v]) => (
                <div className="card" key={k}><div className="n">{v}</div><div className="l"><Badge value={k} /> services</div></div>
              ))}
              <div className="card"><div className="n">{data.total_open_incidents}</div><div className="l">open incidents</div></div>
              <div className="card"><div className="n">{data.pending_recovery_requests}</div><div className="l">pending recovery requests</div></div>
            </div>
            <div className="grid2">
              <div className="panel">
                <BarChart title="Open incidents by severity" data={Object.entries(data.open_incidents_by_severity)
                  .map(([label, value]) => ({ label, value, color: SEV_COLOR[label] }))} />
                <p className="muted"><Link to="/incidents">View incidents →</Link></p>
              </div>
              <div className="panel">
                <h2>Recent deployments</h2>
                <StateView loading={false} empty={data.recent_deployments.length === 0} emptyText="No deployments recorded.">
                  <div className="tablewrap"><table><thead><tr><th>Service</th><th>Version</th><th>Status</th><th>When</th></tr></thead>
                    <tbody>{data.recent_deployments.map((d) => (
                      <tr key={d.id}><td>{d.service_name}</td><td>{d.version}</td><td><Badge value={d.status} /></td><td>{fmtTime(d.deployed_at)}</td></tr>
                    ))}</tbody></table></div>
                </StateView>
              </div>
            </div>
          </>
        )}
      </StateView>
    </>
  );
}
