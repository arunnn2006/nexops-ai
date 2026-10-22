import { NavLink, Outlet, Navigate } from "react-router-dom";
import { useAuth } from "../auth";
import type { Role } from "../types";
import { Badge, Banner } from "./ui";

export function Protected({ minimum }: { minimum?: Role }) {
  const { user, ready, hasRole } = useAuth();
  if (!ready) return <div className="state">Loading…</div>;
  if (!user) return <Navigate to="/login" replace />;
  if (minimum && !hasRole(minimum)) return <Banner tone="warn">This page requires the “{minimum}” role.</Banner>;
  return <Outlet />;
}

export function Layout() {
  const { user, logout, hasRole } = useAuth();
  const links: [string, string][] = [["/", "Dashboard"], ["/services", "Services"], ["/deployments", "Deployments"],
    ["/incidents", "Incidents"], ["/recovery", "Recovery"]];
  if (hasRole("admin")) links.push(["/audit", "Audit"]);
  return (
    <div className="shell">
      <aside className="side">
        <div className="brand">NexOps<span> AI</span></div>
        <nav aria-label="Main">
          {links.map(([to, label]) => <NavLink key={to} to={to} end={to === "/"}>{label}</NavLink>)}
        </nav>
      </aside>
      <div className="main">
        <header className="top">
          <span className="sim-pill" title="Recovery never touches real infrastructure">Recovery: SIMULATED</span>
          <span className="who">{user?.email} {user && <Badge value={user.role} kind="role" />}</span>
          <button onClick={logout}>Sign out</button>
        </header>
        <main><Outlet /></main>
      </div>
    </div>
  );
}
