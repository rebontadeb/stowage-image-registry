import type { ScanKind, ScanView, SigState, VulnSummary } from "../api";
import { Badge } from "./ui";

export function SevBadge({ level }: { level: string }) {
  return <span className={`sev ${level.toLowerCase()}`}>{level}</span>;
}

/** Compact C/H/M/L counts; zeros are muted so real findings stand out. */
export function VulnCounts({ s, levels = ["critical", "high", "medium", "low"] }: { s: Pick<VulnSummary, "critical" | "high" | "medium" | "low">; levels?: ("critical" | "high" | "medium" | "low")[] }) {
  const cell = (n: number, cls: string, label: string) => (
    <span className={`sev ${n > 0 ? cls : "zero"}`} title={`${n} ${label}`} aria-label={`${n} ${label}`}>{n}</span>
  );
  return (
    <span className="sevs" role="group" aria-label="Vulnerabilities by severity">
      {levels.map((l) => cell(s[l], l, l))}
    </span>
  );
}

export function SigBadge({ status, label }: { status: SigState; label?: string }) {
  switch (status) {
    case "signed": return <Badge tone="ok">✓ Signed{label ? ` · ${label}` : ""}</Badge>;
    case "invalid": return <Badge tone="bad">Not trusted</Badge>;
    case "unverified": return <Badge tone="warn">Signed, unverified</Badge>;
    default: return <Badge tone="neutral">Unsigned</Badge>;
  }
}

export const find = (scans: ScanView[] | undefined, digest: string, kind: ScanKind) => scans?.find((s) => s.digest === digest && s.kind === kind);
export const active = (s?: ScanView) => s?.status === "queued" || s?.status === "running";

export function Working({ what }: { what: string }) {
  return <span className="muted"><span className="spin" aria-hidden="true" /> {what}…</span>;
}
