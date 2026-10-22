import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { api, getToken, setToken, setUnauthorizedHandler } from "./api";
import type { Role, User } from "./types";

const RANK: Record<Role, number> = { viewer: 1, operator: 2, admin: 3 };

interface AuthState {
  user: User | null;
  ready: boolean;
  login: (email: string, password: string) => Promise<void>;
  logout: () => void;
  hasRole: (minimum: Role) => boolean;
}
const Ctx = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [ready, setReady] = useState(false);

  const logout = useCallback(() => { setToken(null); setUser(null); }, []);

  useEffect(() => {
    setUnauthorizedHandler(logout);
    if (!getToken()) { setReady(true); return () => setUnauthorizedHandler(null); }
    api.me().then(setUser).catch(() => setToken(null)).finally(() => setReady(true));
    return () => setUnauthorizedHandler(null);
  }, [logout]);

  const login = useCallback(async (email: string, password: string) => {
    const res = await api.login(email, password);
    setToken(res.access_token);
    setUser(res.user);
  }, []);

  // UI gating is a convenience only; the server enforces every permission.
  const hasRole = useCallback((minimum: Role) => !!user && RANK[user.role] >= RANK[minimum], [user]);
  const value = useMemo(() => ({ user, ready, login, logout, hasRole }), [user, ready, login, logout, hasRole]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useAuth(): AuthState {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error("useAuth must be used inside AuthProvider");
  return ctx;
}
