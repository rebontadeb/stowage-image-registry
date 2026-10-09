import { useState, type ReactNode } from "react";
import type { Role, State } from "../api";

const STATE_TONE: Record<State, string> = { running: "ok", starting: "warn", stopped: "neutral", missing: "bad" };
export function StatusBadge({ state }: { state: State }) {
  return <span className={`badge ${STATE_TONE[state]}`}><span className="dot" aria-hidden="true" />{state}</span>;
}

const ROLE_TONE: Record<Role, string> = { admin: "info", operator: "ok", viewer: "neutral" };
export const RoleBadge = ({ role }: { role: Role }) => <span className={`badge ${ROLE_TONE[role]}`}>{role}</span>;

export function Badge({ tone = "neutral", children }: { tone?: "ok" | "warn" | "bad" | "info" | "neutral"; children: ReactNode }) {
  return <span className={`badge ${tone}`}>{children}</span>;
}

export function Alert({ kind = "error", children }: { kind?: "error" | "warn" | "info" | "ok"; children?: ReactNode }) {
  if (!children) return null;
  return <div className={`alert ${kind}`} role={kind === "error" ? "alert" : "status"}><div>{children}</div></div>;
}

export function Field({ label, hint, error, children }: { label: string; hint?: string; error?: string; children: ReactNode }) {
  return (
    <label className="field">
      <span className="label">{label}</span>
      {children}
      {error ? <span className="err" role="alert">{error}</span> : hint && <span className="hint">{hint}</span>}
    </label>
  );
}

export function Code({ children }: { children: string }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try { await navigator.clipboard.writeText(children); setCopied(true); setTimeout(() => setCopied(false), 1500); }
    catch { /* clipboard unavailable on insecure origins; the text stays selectable */ }
  };
  return (
    <div className="code">
      <pre>{children}</pre>
      <button type="button" className="btn secondary sm" onClick={copy} aria-label="Copy to clipboard">{copied ? "Copied" : "Copy"}</button>
    </div>
  );
}

export function Empty({ title, children, action }: { title: string; children?: ReactNode; action?: ReactNode }) {
  return <div className="empty"><h2>{title}</h2>{children && <p>{children}</p>}{action}</div>;
}

/** Determinate when total > 0, otherwise an indeterminate "working" bar. */
export function Progress({ done, total, label }: { done: number; total: number; label: string }) {
  const pct = total > 0 ? Math.min(100, Math.round((done / total) * 100)) : undefined;
  return (
    <div className={`progress${pct === undefined ? " indeterminate" : ""}`} role="progressbar" aria-label={label}
      aria-valuemin={0} aria-valuemax={100} aria-valuenow={pct}>
      <span style={pct === undefined ? undefined : { width: `${pct}%` }} />
    </div>
  );
}

export function Skeleton({ rows = 3 }: { rows?: number }) {
  return (
    <div aria-busy="true" aria-label="Loading" style={{ padding: 18, display: "grid", gap: 12 }}>
      {Array.from({ length: rows }, (_, i) => <span key={i} className="skeleton" style={{ width: `${90 - i * 12}%` }} />)}
    </div>
  );
}

export function PageHead({ title, subtitle, actions, crumbs }: { title: ReactNode; subtitle?: ReactNode; actions?: ReactNode; crumbs?: ReactNode }) {
  return (
    <div className="page-head">
      <div className="grow">
        {crumbs && <div className="breadcrumb">{crumbs}</div>}
        <h1 tabIndex={-1} data-page-title>{title}</h1>
        {subtitle && <p>{subtitle}</p>}
      </div>
      {actions && <div className="row">{actions}</div>}
    </div>
  );
}

export function Kpi({ label, value, sub, tone }: { label: string; value: ReactNode; sub?: ReactNode; tone?: "good" | "warn" | "bad" }) {
  return <div className={`kpi ${tone ?? ""}`}><div className="label">{label}</div><div className="value">{value}</div>{sub && <div className="sub">{sub}</div>}</div>;
}
