import { useMemo, useState } from "react";
import type { Reg, RepoSummary, ScanView, VulnSummary } from "../../api";
import { useDebounced } from "../../hooks";
import { href, go } from "../../router";
import { DataTable, type Column } from "../../components/DataTable";
import { Menu } from "../../components/Menu";
import { Empty } from "../../components/ui";
import { VulnCounts } from "../../components/security";

/** Worst scanned image of a repository (most critical, then high, then medium findings). */
function worst(scans: ScanView[], repo: string): VulnSummary | undefined {
  let best: VulnSummary | undefined;
  const score = (v: VulnSummary) => v.critical * 1e6 + v.high * 1e3 + v.medium;
  for (const x of scans) {
    if (x.repo !== repo || x.kind !== "vuln" || x.status !== "done") continue;
    const v = x.summary as unknown as VulnSummary;
    if (!best || score(v) > score(best)) best = v;
  }
  return best;
}

export function RepoList({ reg, summaries, loading, scans, secOn, canOperate, busy, onAdd, onDeleteRepo, onGC }: {
  reg: Reg; summaries?: RepoSummary[]; loading: boolean; scans: ScanView[]; secOn: boolean; canOperate: boolean; busy: boolean;
  onAdd: () => void; onDeleteRepo: (name: string, tags: number) => void; onGC: () => void;
}) {
  const [q, setQ] = useState("");
  const dq = useDebounced(q.trim().toLowerCase());
  const rows = useMemo(() => (summaries ?? []).filter((r) => !dq || r.name.includes(dq)), [summaries, dq]);
  const open = (r: RepoSummary) => go("registries", reg.name, "images", r.name);

  const columns: Column<RepoSummary>[] = [
    { key: "name", header: "Repository", sort: (r) => r.name, render: (r) => <a className="repo-name" href={href("registries", reg.name, "images", r.name)}>{r.name}</a> },
    { key: "tags", header: "Tags", align: "right", sort: (r) => r.tags, render: (r) => <span className="num">{r.tags}</span> },
    ...(secOn ? [{
      key: "vuln", header: "Vulnerabilities", sort: (r: RepoSummary) => { const w = worst(scans, r.name); return w ? w.critical * 1000 + w.high : null; },
      render: (r: RepoSummary) => { const w = worst(scans, r.name); return w ? <VulnCounts s={w} levels={["critical", "high", "medium"]} /> : <span className="muted">Not scanned</span>; },
    }] : []),
    ...(canOperate ? [{
      key: "act", header: "", align: "right" as const,
      render: (r: RepoSummary) => <button className="btn danger sm" disabled={busy} onClick={() => onDeleteRepo(r.name, r.tags)} aria-label={`Delete repository ${r.name}`}>Delete</button>,
    }] : []),
  ];

  return (
    <>
      <div className="toolbar">
        <div className="search">
          <label className="sr-only" htmlFor="repo-q">Search repositories</label>
          <input id="repo-q" className="input" type="search" placeholder="Search repositories" value={q} onChange={(e) => setQ(e.target.value)} />
        </div>
        <span className="spacer" />
        {canOperate && <button className="btn" onClick={onAdd}>Add image</button>}
        {canOperate && <Menu label="More actions" items={[{ label: "Free disk space…", onSelect: onGC }]} />}
      </div>
      <div className="card flush">
        <DataTable roomy columns={columns} rows={rows} rowKey={(r) => r.name} caption="Repositories" loading={loading && !summaries}
          initialSort={{ key: "name", dir: "asc" }} pageSizes={[10, 25, 50]} resetKey={dq} onRowOpen={open}
          empty={dq
            ? <Empty title="No repositories match">Try a different search.</Empty>
            : <Empty title="No images yet" action={canOperate ? <button className="btn" onClick={onAdd}>Add image</button> : undefined}>
                Push one with <code>podman push</code>, or add one here.
              </Empty>} />
      </div>
    </>
  );
}
