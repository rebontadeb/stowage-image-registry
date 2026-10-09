import { useMemo, useState, type ReactNode } from "react";
import { api, type OVALReport, type SBOMReport, type ScanKind, type ScanView, type SigResult, type Vuln, type VulnReport } from "../../api";
import { fmtDate, timeAgo, useAction, useLoad } from "../../hooks";
import { Dialog } from "../../components/dialog";
import { DataTable, type Column } from "../../components/DataTable";
import { Alert, Badge, Empty, Skeleton } from "../../components/ui";
import { SevBadge, SigBadge, Working, active, find } from "../../components/security";

type Tab = ScanKind;
const TABS: { id: Tab; label: string }[] = [
  { id: "vuln", label: "Vulnerabilities" }, { id: "sbom", label: "SBOM" }, { id: "sig", label: "Signature" }, { id: "oval", label: "Red Hat OVAL" },
];

export interface ScanDialogProps {
  reg: string; repo: string; tag: string; digest: string;
  scans: ScanView[]; canOperate: boolean; hasSigningKey: boolean;
  onRun: (kinds: ScanKind[]) => Promise<void>; onSign: () => Promise<void>; onClose: () => void;
}

export function ScanDialog(p: ScanDialogProps) {
  const [tab, setTab] = useState<Tab>("vuln");
  return (
    <Dialog title={`${p.repo}:${p.tag}`} onClose={p.onClose} wide xl footer={<button className="btn secondary" onClick={p.onClose}>Close</button>}>
      <p className="muted mono" style={{ marginTop: 0 }}>{p.digest}</p>
      <div className="tabs inner" role="tablist" aria-label="Scan results">
        {TABS.map((t) => (
          <button key={t.id} role="tab" id={`tab-${t.id}`} aria-selected={tab === t.id} aria-controls={`panel-${t.id}`} onClick={() => setTab(t.id)}>{t.label}</button>
        ))}
      </div>
      <div role="tabpanel" id={`panel-${tab}`} aria-labelledby={`tab-${tab}`}>
        {tab === "vuln" && <VulnTab {...p} />}
        {tab === "sbom" && <SbomTab {...p} />}
        {tab === "sig" && <SigTab {...p} />}
        {tab === "oval" && <OvalTab {...p} />}
      </div>
    </Dialog>
  );
}

/** Handles the "not run / running / failed" states shared by every result tab. */
function Gate({ p, kind, what, intro, children }: { p: ScanDialogProps; kind: ScanKind; what: string; intro: string; children: (s: ScanView) => ReactNode }) {
  const s = find(p.scans, p.digest, kind);
  const act = useAction();
  const run = () => act.run(() => p.onRun([kind]));
  if (!s) {
    return (
      <Empty title={`No ${what} yet`} action={p.canOperate ? <button className="btn" disabled={act.busy} onClick={run}>{act.busy ? "Starting…" : `Run ${what}`}</button> : undefined}>
        {intro}{!p.canOperate && " An operator can run it."}
        {act.error && <Alert>{act.error}</Alert>}
      </Empty>
    );
  }
  if (active(s)) return <div className="empty"><Working what={s.status === "queued" ? `Waiting to run ${what}` : `Running ${what}`} /></div>;
  if (s.status === "failed") {
    return (
      <>
        <Alert>{`${what} failed: ${s.error ?? "unknown error"}`}</Alert>
        {p.canOperate && <button className="btn secondary" disabled={act.busy} onClick={run}>Try again</button>}
      </>
    );
  }
  return (
    <>
      {children(s)}
      <div className="row" style={{ marginTop: 14 }}>
        <span className="muted">{s.tool ? `${s.tool} · ` : ""}finished {s.finished ? timeAgo(s.finished) : "—"}{s.by ? ` · by ${s.by}` : ""}</span>
        <span className="spacer" />
        {p.canOperate && <button className="btn secondary sm" disabled={act.busy} onClick={run}>Run again</button>}
      </div>
    </>
  );
}

// ---------- vulnerabilities ----------

const RANK: Record<string, number> = { Critical: 0, High: 1, Medium: 2, Low: 3, Negligible: 4, Unknown: 5 };

function VulnTab(p: ScanDialogProps) {
  return (
    <Gate p={p} kind="vuln" what="vulnerability scan" intro="Checks the image's packages against known vulnerabilities (grype).">
      {(s) => <VulnResult p={p} scan={s} />}
    </Gate>
  );
}

function VulnResult({ p, scan }: { p: ScanDialogProps; scan: ScanView }) {
  const rep = useLoad(() => api.scanResult<VulnReport>(p.reg, p.repo, p.digest, "vuln"), [p.reg, p.digest, scan.finished]);
  const [sev, setSev] = useState("");
  const [fixable, setFixable] = useState(false);
  const [q, setQ] = useState("");
  const rows = useMemo(() => (rep.data?.vulns ?? []).filter((v) =>
    (!sev || v.severity === sev) && (!fixable || v.fixedIn.length > 0) &&
    (!q || `${v.id} ${v.package}`.toLowerCase().includes(q.toLowerCase()))), [rep.data, sev, fixable, q]);
  if (rep.error) return <Alert>{rep.error}</Alert>;
  if (!rep.data) return <Skeleton rows={4} />;
  const s = rep.data.summary;

  const cols: Column<Vuln>[] = [
    { key: "id", header: "Vulnerability", sort: (v) => v.id, render: (v) => <VulnLink v={v} /> },
    { key: "sev", header: "Severity", sort: (v) => RANK[v.severity] ?? 9, render: (v) => <SevBadge level={v.severity} /> },
    { key: "score", header: "CVSS", align: "right", sort: (v) => v.score ?? null, render: (v) => <span className="num">{v.score ? v.score.toFixed(1) : "—"}</span> },
    { key: "pkg", header: "Package", sort: (v) => v.package, render: (v) => <><span className="mono">{v.package}</span> <span className="muted mono">{v.version}</span></> },
    { key: "fix", header: "Fixed in", sort: (v) => v.fixedIn[0] ?? "~", render: (v) => v.fixedIn.length ? <span className="mono">{v.fixedIn.join(", ")}</span> : <span className="muted">{v.fixState === "wont-fix" ? "won't fix" : "no fix yet"}</span> },
  ];

  return (
    <>
      <div className="stat-row" aria-label="Summary">
        {([["Critical", s.critical, "critical"], ["High", s.high, "high"], ["Medium", s.medium, "medium"], ["Low", s.low + s.negligible, "low"]] as const).map(([l, n, c]) => (
          <div key={l} className="stat"><div className="n"><span className={`sev ${n > 0 ? c : "zero"}`}>{n}</span></div><div className="l">{l}</div></div>
        ))}
        <div className="stat"><div className="n num">{s.fixable}</div><div className="l">with a fix</div></div>
        <div className="stat"><div className="n num">{s.total}</div><div className="l">total</div></div>
      </div>
      {s.total === 0 ? <Alert kind="ok">No known vulnerabilities found.</Alert> : (
        <>
          <div className="filters">
            <label className="sr-only" htmlFor="v-q">Search vulnerabilities</label>
            <input id="v-q" className="input" type="search" placeholder="Search CVE or package" value={q} onChange={(e) => setQ(e.target.value)} />
            <label className="sr-only" htmlFor="v-sev">Severity</label>
            <select id="v-sev" className="input" value={sev} onChange={(e) => setSev(e.target.value)}>
              <option value="">All severities</option>{["Critical", "High", "Medium", "Low", "Negligible", "Unknown"].map((x) => <option key={x}>{x}</option>)}
            </select>
            <label className="check" style={{ margin: 0 }}><input type="checkbox" checked={fixable} onChange={(e) => setFixable(e.target.checked)} /> Fix available</label>
            <span className="muted">{rows.length} shown</span>
          </div>
          <div className="card flush" style={{ marginBottom: 0 }}>
            <DataTable columns={cols} rows={rows} rowKey={(v) => `${v.id}|${v.package}|${v.version}`} caption="Vulnerabilities"
              initialSort={{ key: "sev", dir: "asc" }} pageSizes={[10, 25, 50, 100]} resetKey={`${sev}|${fixable}|${q}`}
              empty={<Empty title="No matches">Change the filters to see more.</Empty>} />
          </div>
        </>
      )}
      {s.dbBuilt && <p className="muted" style={{ marginTop: 10 }}>Vulnerability database built {fmtDate(s.dbBuilt)}. Run the scan again to pick up newer data.</p>}
    </>
  );
}

function VulnLink({ v }: { v: Vuln }) {
  const href = v.id.startsWith("CVE-") ? `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(v.id)}`
    : v.id.startsWith("GHSA-") ? `https://github.com/advisories/${encodeURIComponent(v.id)}` : v.url;
  return href ? <a href={href} target="_blank" rel="noopener noreferrer">{v.id}<span className="sr-only"> (opens in a new tab)</span></a> : <>{v.id}</>;
}

// ---------- SBOM ----------

function SbomTab(p: ScanDialogProps) {
  return (
    <Gate p={p} kind="sbom" what="SBOM" intro="Lists every package and library inside the image (syft) so it can be audited or exported.">
      {(s) => <SbomResult p={p} scan={s} />}
    </Gate>
  );
}

function SbomResult({ p, scan }: { p: ScanDialogProps; scan: ScanView }) {
  const rep = useLoad(() => api.scanResult<SBOMReport>(p.reg, p.repo, p.digest, "sbom"), [p.reg, p.digest, scan.finished]);
  const [q, setQ] = useState("");
  const [type, setType] = useState("");
  const rows = useMemo(() => (rep.data?.components ?? []).filter((c) => (!type || c.type === type) && (!q || `${c.name} ${c.version}`.toLowerCase().includes(q.toLowerCase()))), [rep.data, q, type]);
  if (rep.error) return <Alert>{rep.error}</Alert>;
  if (!rep.data) return <Skeleton rows={4} />;
  const sum = rep.data.summary;
  const cols: Column<(typeof rows)[number]>[] = [
    { key: "n", header: "Package", sort: (c) => c.name.toLowerCase(), render: (c) => <span className="mono">{c.name}</span> },
    { key: "v", header: "Version", sort: (c) => c.version, render: (c) => <span className="mono">{c.version || "—"}</span> },
    { key: "t", header: "Type", sort: (c) => c.type, render: (c) => <Badge>{c.type}</Badge> },
    { key: "l", header: "License", className: "hide-sm", render: (c) => c.licenses?.join(", ") || <span className="muted">—</span> },
  ];
  return (
    <>
      <div className="row" style={{ marginBottom: 12 }}>
        <span><strong className="num">{sum.packages}</strong> packages{sum.files > 0 && <span className="muted"> · {sum.files} files not listed</span>} <span className="muted">· {sum.format}</span></span>
        <span className="spacer" />
        <a className="btn secondary sm" href={api.downloadUrl(p.reg, p.repo, p.digest, "cyclonedx")} download>Download CycloneDX</a>
        <a className="btn secondary sm" href={api.downloadUrl(p.reg, p.repo, p.digest, "spdx")} download>Download SPDX</a>
      </div>
      <div className="filters">
        <label className="sr-only" htmlFor="s-q">Search packages</label>
        <input id="s-q" className="input" type="search" placeholder="Search packages" value={q} onChange={(e) => setQ(e.target.value)} />
        <label className="sr-only" htmlFor="s-t">Package type</label>
        <select id="s-t" className="input" value={type} onChange={(e) => setType(e.target.value)}>
          <option value="">All types</option>{Object.entries(sum.byType).filter(([t]) => t !== "file").map(([t, n]) => <option key={t} value={t}>{t} ({n})</option>)}
        </select>
      </div>
      <div className="card flush" style={{ marginBottom: 0 }}>
        <DataTable columns={cols} rows={rows} rowKey={(c) => `${c.purl || c.name}|${c.version}|${c.type}`} caption="Software bill of materials"
          initialSort={{ key: "n", dir: "asc" }} pageSizes={[10, 25, 50, 100]} resetKey={`${q}|${type}`} empty={<Empty title="No packages match" />} />
      </div>
    </>
  );
}

// ---------- signature ----------

const SIG_TEXT: Record<string, string> = {
  signed: "This exact image was signed by a key you trust. It has not been modified since.",
  unsigned: "No signature was found for this image.",
  invalid: "A signature exists, but none of this registry's trusted keys verify it. Someone else signed it, or it was signed with a key you have not added.",
  unverified: "A signature exists, but this registry has no trusted keys yet, so it cannot be verified. Add the signer's public key in the Security tab.",
};

function SigTab(p: ScanDialogProps) {
  const act = useAction();
  const sign = () => act.run(p.onSign);
  return (
    <Gate p={p} kind="sig" what="signature check" intro="Verifies the image's signature against the keys this registry trusts (cosign).">
      {(s) => <SigResult p={p} scan={s} sign={sign} busy={act.busy} error={act.error} />}
    </Gate>
  );
}

function SigResult({ p, scan, sign, busy, error }: { p: ScanDialogProps; scan: ScanView; sign: () => void; busy: boolean; error?: string }) {
  const rep = useLoad(() => api.scanResult<SigResult>(p.reg, p.repo, p.digest, "sig"), [p.reg, p.digest, scan.finished]);
  if (rep.error) return <Alert>{rep.error}</Alert>;
  if (!rep.data) return <Skeleton rows={2} />;
  const r = rep.data;
  return (
    <>
      <p><SigBadge status={r.status} label={r.key} /></p>
      <p>{SIG_TEXT[r.status]}</p>
      {r.attempts.length > 0 && (
        <ul className="plain" aria-label="Keys tried">{r.attempts.map((a) => <li key={a.key}><span>{a.key}</span><span className="spacer" /><Badge tone={a.status === "signed" ? "ok" : "neutral"}>{a.status}</Badge></li>)}</ul>
      )}
      <Alert>{error}</Alert>
      {p.canOperate && (
        <div style={{ marginTop: 12 }}>
          {p.hasSigningKey
            ? <button className="btn" onClick={sign} disabled={busy}>{busy ? "Signing…" : r.status === "signed" ? "Sign again" : "Sign this image"}</button>
            : <span className="muted">This registry has no signing key. An administrator can create one in the Security tab to sign images from here.</span>}
        </div>
      )}
    </>
  );
}

// ---------- Red Hat OVAL ----------

function OvalTab(p: ScanDialogProps) {
  return (
    <Gate p={p} kind="oval" what="OVAL check" intro="For RHEL and UBI images: evaluates Red Hat's own security advisories against the packages in the image (OpenSCAP). Needs OVAL content, added by an administrator under Security tools, and a podman host.">
      {(s) => <OvalResult p={p} scan={s} />}
    </Gate>
  );
}

function OvalResult({ p, scan }: { p: ScanDialogProps; scan: ScanView }) {
  const rep = useLoad(() => api.scanResult<OVALReport>(p.reg, p.repo, p.digest, "oval"), [p.reg, p.digest, scan.finished]);
  if (rep.error) return <Alert>{rep.error}</Alert>;
  if (!rep.data) return <Skeleton rows={4} />;
  const { summary: s, findings } = rep.data;
  if (!s.applicable) return <Alert kind="info">{s.reason ?? "Not applicable to this image."}{s.os ? ` (${s.os})` : ""}</Alert>;
  const cols: Column<(typeof findings)[number]>[] = [
    { key: "a", header: "Advisory", className: "nw", sort: (f) => f.advisory, render: (f) => f.url ? <a href={f.url} target="_blank" rel="noopener noreferrer">{f.advisory || f.definition}<span className="sr-only"> (opens in a new tab)</span></a> : <>{f.advisory || f.definition}</> },
    { key: "s", header: "Severity", sort: (f) => ["Critical", "Important", "Moderate", "Low"].indexOf(f.severity), render: (f) => <SevBadge level={f.severity} /> },
    { key: "t", header: "Summary", render: (f) => f.title.replace(/^RH[A-Z]{2}-\d+:\d+:\s*/, "").replace(/\s*\((Critical|Important|Moderate|Low)\)$/, "") },
    { key: "c", header: "CVEs", className: "hide-sm", render: (f) => <span className="mono">{f.cves.slice(0, 3).join(", ")}{f.cves.length > 3 ? ` +${f.cves.length - 3}` : ""}</span> },
  ];
  return (
    <>
      <p className="muted" style={{ marginTop: 0 }}>{s.os} · {s.definitions} Red Hat definitions from <code>{s.content}</code> evaluated.</p>
      <div className="stat-row">
        {([["Critical", s.critical, "critical"], ["Important", s.important, "important"], ["Moderate", s.moderate, "moderate"], ["Low", s.low, "low"]] as const).map(([l, n, c]) => (
          <div key={l} className="stat"><div className="n"><span className={`sev ${n > 0 ? c : "zero"}`}>{n}</span></div><div className="l">{l}</div></div>
        ))}
        <div className="stat"><div className="n num">{s.vulnerable}</div><div className="l">advisories apply</div></div>
      </div>
      {s.vulnerable === 0 ? <Alert kind="ok">No applicable Red Hat advisories: the image is up to date for this content.</Alert> : (
        <>
          <div className="row end" style={{ marginBottom: 10 }}><a className="btn secondary sm" href={api.downloadUrl(p.reg, p.repo, p.digest, "oval-report")} download>Download full OpenSCAP report</a></div>
          <div className="card flush" style={{ marginBottom: 0 }}>
            <DataTable columns={cols} rows={findings} rowKey={(f) => f.definition} caption="Applicable Red Hat advisories" initialSort={{ key: "s", dir: "asc" }} pageSizes={[10, 25, 50]} empty={<Empty title="None" />} />
          </div>
        </>
      )}
    </>
  );
}
