import { useCallback, useEffect, useRef, useState } from "react";

export function useLoad<T>(fn: () => Promise<T>, deps: unknown[], pollMs = 0) {
  const [data, setData] = useState<T>();
  const [error, setError] = useState<string>();
  const [loading, setLoading] = useState(true);
  const fnRef = useRef(fn);
  fnRef.current = fn;
  const alive = useRef(true);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);

  const reload = useCallback(async () => {
    try {
      const v = await fnRef.current();
      if (alive.current) { setData(v); setError(undefined); }
    } catch (e) {
      if (alive.current) setError((e as Error).message);
    } finally {
      if (alive.current) setLoading(false);
    }
  }, []);

  useEffect(() => {
    setLoading(true);
    reload();
    if (!pollMs) return;
    const t = setInterval(() => { if (!document.hidden) reload(); }, pollMs);
    return () => clearInterval(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, pollMs, reload]);

  return { data, error, loading, reload };
}

/** Runs a mutation, tracking busy/error state. Resolves to true on success. */
export function useAction() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const run = useCallback(async (fn: () => Promise<unknown>) => {
    setBusy(true);
    setError(undefined);
    try { await fn(); return true; }
    catch (e) { setError((e as Error).message); return false; }
    finally { setBusy(false); }
  }, []);
  return { busy, error, run, clear: () => setError(undefined) };
}

export function useDebounced<T>(value: T, ms = 250): T {
  const [v, setV] = useState(value);
  useEffect(() => { const t = setTimeout(() => setV(value), ms); return () => clearTimeout(t); }, [value, ms]);
  return v;
}

export function fmtBytes(n: number | null | undefined): string {
  if (n === null || n === undefined) return "—";
  if (n < 1024) return `${n} B`;
  const u = ["KB", "MB", "GB", "TB"];
  let i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
  return `${n.toFixed(n < 10 ? 1 : 0)} ${u[i]}`;
}

export const fmtDate = (s?: string) => (s && !s.startsWith("0001") ? new Date(s).toLocaleString() : "—");

export function timeAgo(s: string): string {
  const sec = Math.max(0, Math.round((Date.now() - new Date(s).getTime()) / 1000));
  if (sec < 45) return "just now";
  if (sec < 3600) return `${Math.round(sec / 60)} min ago`;
  if (sec < 86400) return `${Math.round(sec / 3600)} h ago`;
  const d = Math.round(sec / 86400);
  return d === 1 ? "yesterday" : `${d} days ago`;
}

export function useTitle(t: string) {
  useEffect(() => { document.title = `${t} · Stowage`; }, [t]);
}

/** Tracks a media query, e.g. useMedia("(max-width: 900px)"). */
export function useMedia(query: string): boolean {
  const get = () => (typeof window !== "undefined" && window.matchMedia ? window.matchMedia(query).matches : false);
  const [m, setM] = useState(get);
  useEffect(() => {
    const mq = window.matchMedia(query);
    const on = () => setM(mq.matches);
    on();
    mq.addEventListener("change", on);
    return () => mq.removeEventListener("change", on);
  }, [query]);
  return m;
}
