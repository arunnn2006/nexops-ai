import { BrowserRouter, Route, Routes } from "react-router-dom";
import { AuthProvider } from "./auth";
import { Layout, Protected } from "./components/Layout";
import { AuditPage } from "./pages/Audit";
import { LoginPage, RegisterPage } from "./pages/Auth";
import { DashboardPage } from "./pages/Dashboard";
import { DeploymentsPage } from "./pages/Deployments";
import { IncidentDetailPage } from "./pages/IncidentDetail";
import { IncidentsPage } from "./pages/Incidents";
import { RecoveryPage } from "./pages/Recovery";
import { ServicesPage } from "./pages/Services";

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route path="/register" element={<RegisterPage />} />
          <Route element={<Protected />}>
            <Route element={<Layout />}>
              <Route index element={<DashboardPage />} />
              <Route path="services" element={<ServicesPage />} />
              <Route path="deployments" element={<DeploymentsPage />} />
              <Route path="incidents" element={<IncidentsPage />} />
              <Route path="incidents/:id" element={<IncidentDetailPage />} />
              <Route path="recovery" element={<RecoveryPage />} />
              <Route element={<Protected minimum="admin" />}>
                <Route path="audit" element={<AuditPage />} />
              </Route>
            </Route>
          </Route>
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
}
