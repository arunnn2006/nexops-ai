import { useCallback, useEffect, useState, type ReactNode } from "react";

export function useAsync<T>(fn: () => Promise<T>, deps: unknown[]) {
  const [state, setState] = useState<{ data?: T; error?: string; loading: boolean }>({ loading: true });
  const [tick, setTick] = useState(0);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const run = useCallback(fn, deps);
  useEffect(() => {
    let alive = true;
    setState((s) => ({ ...s, loading: true, error: undefined }));
    run()
      .then((data) => alive && setState({ data, loading: false }))
      .catch((e) => alive && setState({ loading: false, error: e instanceof Error ? e.message : "Request failed" }));
    return () => { alive = false; };
  }, [run, tick]);
  return { ...state, reload: () => setTick((t) => t + 1) };
}

export const fmtTime = (iso: string | null | undefined) => (iso ? new Date(iso).toLocaleString() : "—");

export function Badge({ value, kind }: { value: string; kind?: string }) {
  return <span className={`badge ${kind ?? "b"}-${value}`}>{value.replace(/_/g, " ")}</span>;
}

export function Banner({ tone, children }: { tone: "info" | "warn" | "ok" | "error"; children: ReactNode }) {
  return <div className={`banner ${tone}`} role={tone === "error" ? "alert" : "status"}>{children}</div>;
}

export function StateView({ loading, error, empty, emptyText, onRetry, children }: {
  loading: boolean; error?: string; empty?: boolean; emptyText?: string; onRetry?: () => void; children: ReactNode;
}) {
  if (loading) return <div className="state" aria-busy="true">Loading…</div>;
  if (error) {
    return (
      <div className="state error" role="alert">
        <p>{error}</p>
        {onRetry && <button onClick={onRetry}>Retry</button>}
      </div>
    );
  }
  if (empty) return <div className="state">{emptyText ?? "Nothing to show yet."}</div>;
  return <>{children}</>;
}
