import { useState, type FormEvent } from "react";
import { Link, Navigate, useNavigate } from "react-router-dom";
import { api, ApiError } from "../api";
import { useAuth } from "../auth";
import { Banner } from "../components/ui";

export function LoginPage() {
  const { login, user } = useAuth();
  const nav = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  if (user) return <Navigate to="/" replace />;

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true); setError(null);
    try { await login(email, password); nav("/"); }
    catch (err) { setError(err instanceof ApiError ? err.message : "Sign-in failed"); }
    finally { setBusy(false); }
  }
  return (
    <div className="panel auth">
      <h1>Sign in to NexOps AI</h1>
      <form onSubmit={submit}>
        <label>Email<input type="email" required value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="username" /></label>
        <label>Password<input type="password" required value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" /></label>
        {error && <Banner tone="error">{error}</Banner>}
        <button type="submit" disabled={busy}>{busy ? "Signing in…" : "Sign in"}</button>
      </form>
      <p className="muted">No account? <Link to="/register">Register</Link></p>
    </div>
  );
}

export function RegisterPage() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    if (password.length < 12) { setError("Password must be at least 12 characters."); return; }
    setBusy(true);
    try { await api.register(email, password); setDone(true); }
    catch (err) { setError(err instanceof ApiError ? err.message : "Registration failed"); }
    finally { setBusy(false); }
  }
  if (done) {
    return (
      <div className="panel auth">
        <Banner tone="ok">Account created with the read-only “viewer” role. An admin must raise your role for write access.</Banner>
        <Link to="/login">Go to sign in</Link>
      </div>
    );
  }
  return (
    <div className="panel auth">
      <h1>Create account</h1>
      <form onSubmit={submit}>
        <label>Email<input type="email" required value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="username" /></label>
        <label>Password (12+ characters)<input type="password" required value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" /></label>
        {error && <div className="field-err" role="alert">{error}</div>}
        <button type="submit" disabled={busy}>{busy ? "Creating…" : "Register"}</button>
      </form>
      <p className="muted">Already registered? <Link to="/login">Sign in</Link></p>
    </div>
  );
}
