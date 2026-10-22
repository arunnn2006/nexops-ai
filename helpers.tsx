import { act, render } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import type { ReactElement } from "react";
import { vi } from "vitest";
import { api, setToken } from "../api";
import { AuthProvider } from "../auth";
import type { Role, User } from "../types";

export const mkUser = (role: Role): User => ({ id: 1, email: `${role}@test.dev`, role, is_active: true, created_at: "2026-01-01T00:00:00Z" });

export async function renderAs(role: Role | null, ui: ReactElement, route = "/") {
  if (role) { setToken("tok"); vi.spyOn(api, "me").mockResolvedValue(mkUser(role)); }
  let out!: ReturnType<typeof render>;
  await act(async () => {
    out = render(<AuthProvider><MemoryRouter initialEntries={[route]}>{ui}</MemoryRouter></AuthProvider>);
  });
  return out;
}
