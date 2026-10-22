import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Route, Routes } from "react-router-dom";
import { api, ApiError } from "../api";
import { LineChart } from "../components/charts";
import { Protected } from "../components/Layout";
import { LoginPage, RegisterPage } from "../pages/Auth";
import { DiagnosisView } from "../pages/IncidentDetail";
import { IncidentsPage } from "../pages/Incidents";
import { RecoveryPage } from "../pages/Recovery";
import type { Diagnosis, Incident, RecoveryRequest } from "../types";
import { renderAs } from "./helpers";

afterEach(() => vi.restoreAllMocks());

const incident = (o: Partial<Incident> = {}): Incident => ({
  id: 1, title: "High error rate: checkout-api", rule: "high_error_rate", severity: "high", status: "open", service_id: 1,
  service_name: "checkout-api", subject: "service:checkout-api", summary: "s", detected_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-01T00:00:00Z", resolved_at: null, ...o,
});
const rec = (o: Partial<RecoveryRequest> = {}): RecoveryRequest => ({
  id: 5, incident_id: 1, service_id: 1, service_name: "demo-svc", action: "restart_service", reason: "", status: "pending",
  mode: "simulated", requested_by_email: "operator@test.dev", decided_by_email: null, decision_note: "",
  created_at: "2026-01-01T00:00:00Z", decided_at: null, executed_at: null, result: null, verification: null, ...o,
});

describe("auth screens", () => {
  it("shows the server error on failed login", async () => {
    vi.spyOn(api, "login").mockRejectedValue(new ApiError(401, "Invalid email or password"));
    await renderAs(null, <LoginPage />);
    await userEvent.type(screen.getByLabelText("Email"), "a@b.co");
    await userEvent.type(screen.getByLabelText("Password"), "wrong");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Invalid email or password");
  });

  it("registration rejects short passwords without calling the API", async () => {
    const reg = vi.spyOn(api, "register");
    await renderAs(null, <RegisterPage />);
    await userEvent.type(screen.getByLabelText("Email"), "a@b.co");
    await userEvent.type(screen.getByLabelText(/Password/), "short");
    await userEvent.click(screen.getByRole("button", { name: "Register" }));
    expect(screen.getByRole("alert")).toHaveTextContent("at least 12");
    expect(reg).not.toHaveBeenCalled();
  });

  it("registration success explains the viewer role", async () => {
    vi.spyOn(api, "register").mockResolvedValue({ id: 2, email: "a@b.co", role: "viewer", is_active: true, created_at: "" });
    await renderAs(null, <RegisterPage />);
    await userEvent.type(screen.getByLabelText("Email"), "a@b.co");
    await userEvent.type(screen.getByLabelText(/Password/), "a-long-enough-pass");
    await userEvent.click(screen.getByRole("button", { name: "Register" }));
    expect(await screen.findByText(/read-only/)).toBeInTheDocument();
  });
});

describe("route guard", () => {
  it("redirects anonymous users and blocks insufficient roles", async () => {
    const tree = (
      <Routes><Route path="/login" element={<div>login page</div>} />
        <Route element={<Protected minimum="admin" />}><Route path="/" element={<div>secret</div>} /></Route></Routes>
    );
    const { unmount } = await renderAs(null, tree);
    expect(await screen.findByText("login page")).toBeInTheDocument();
    unmount();
    await renderAs("operator", tree);
    expect(await screen.findByText(/requires the “admin” role/)).toBeInTheDocument();
    expect(screen.queryByText("secret")).not.toBeInTheDocument();
  });
});

describe("incidents list", () => {
  it("renders rows, and hides the detection button from viewers", async () => {
    vi.spyOn(api, "incidents").mockResolvedValue({ items: [incident()], total: 1 });
    await renderAs("viewer", <IncidentsPage />);
    expect(await screen.findByText("High error rate: checkout-api")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Run detection/ })).not.toBeInTheDocument();
  });

  it("shows empty and error states", async () => {
    const spy = vi.spyOn(api, "incidents").mockResolvedValue({ items: [], total: 0 });
    const { unmount } = await renderAs("viewer", <IncidentsPage />);
    expect(await screen.findByText(/No incidents match/)).toBeInTheDocument();
    unmount();
    spy.mockRejectedValue(new Error("boom"));
    await renderAs("viewer", <IncidentsPage />);
    expect(await screen.findByRole("alert")).toHaveTextContent("boom");
    expect(screen.getByRole("button", { name: "Retry" })).toBeInTheDocument();
  });

  it("operators can run detection and see the result", async () => {
    vi.spyOn(api, "incidents").mockResolvedValue({ items: [], total: 0 });
    vi.spyOn(api, "detect").mockResolvedValue({ created: 3 });
    await renderAs("operator", <IncidentsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /Run detection/ }));
    expect(await screen.findByText(/3 new incident/)).toBeInTheDocument();
  });
});

describe("diagnosis view", () => {
  const dx: Diagnosis = {
    id: 1, incident_id: 1, generated_at: "2026-01-01T00:00:00Z", method: "deterministic", summary: "sum",
    facts: [{ type: "fact", text: "5 failed logins", evidence_id: 3, kind: "security_event" }],
    hypotheses: [{ type: "hypothesis", statement: "Looks like guessing", confidence: "medium", supporting_evidence_ids: [3], missing_evidence: ["IP reputation"] }],
    next_steps: ["Check with the owner"], limitations: ["No external AI"],
  };
  it("separates observed facts from unconfirmed hypotheses", async () => {
    await renderAs("viewer", <DiagnosisView dx={dx} />);
    expect(screen.getByText("Observed facts")).toBeInTheDocument();
    expect(screen.getByText(/Hypotheses \(not confirmed\)/)).toBeInTheDocument();
    expect(screen.getByText(/not a confirmed cause/)).toBeInTheDocument();
    expect(screen.getByText(/Supported by evidence: #3/)).toBeInTheDocument();
    expect(screen.getByText(/IP reputation/)).toBeInTheDocument();
    expect(screen.getByText("No external AI")).toBeInTheDocument();
  });
});

describe("recovery approvals", () => {
  it("clearly labels simulated mode and hides approval from operators", async () => {
    vi.spyOn(api, "recoveryRequests").mockResolvedValue([rec()]);
    await renderAs("operator", <RecoveryPage />);
    expect(await screen.findByText(/SIMULATED MODE/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Approve" })).not.toBeInTheDocument();
    expect(screen.getByText(/Waiting for an admin/)).toBeInTheDocument();
  });

  it("admins can approve", async () => {
    vi.spyOn(api, "recoveryRequests").mockResolvedValue([rec()]);
    const decide = vi.spyOn(api, "decide").mockResolvedValue(rec({ status: "approved" }));
    await renderAs("admin", <RecoveryPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Approve" }));
    await waitFor(() => expect(decide).toHaveBeenCalledWith(5, "approve", ""));
  });

  it("execute stays disabled until the exact phrase is typed", async () => {
    vi.spyOn(api, "recoveryRequests").mockResolvedValue([rec({ status: "approved" })]);
    const exec = vi.spyOn(api, "execute").mockResolvedValue(rec({ status: "executed" }));
    await renderAs("operator", <RecoveryPage />);
    const button = await screen.findByRole("button", { name: /Execute \(simulated\)/ });
    expect(button).toBeDisabled();
    const input = screen.getByLabelText("Confirmation for request 5");
    await userEvent.type(input, "restart_service demo");
    expect(button).toBeDisabled();
    await userEvent.type(input, "-svc");
    expect(button).toBeEnabled();
    await userEvent.click(button);
    await waitFor(() => expect(exec).toHaveBeenCalledWith(5, "restart_service demo-svc"));
  });
});

describe("charts", () => {
  it("draws a polyline per series and handles no data", () => {
    const { unmount } = render__(<LineChart title="Latency" labels={["a", "b"]} series={[{ label: "l", color: "#fff", values: [1, 5] }]} />);
    expect(screen.getAllByTestId("line")).toHaveLength(1);
    expect(screen.getByRole("img", { name: /Latency/ })).toBeInTheDocument();
    unmount();
    render__(<LineChart title="Empty" labels={[]} series={[{ label: "l", color: "#fff", values: [] }]} />);
    expect(screen.getByText("No data points.")).toBeInTheDocument();
  });
});
import { render as render__ } from "@testing-library/react";
