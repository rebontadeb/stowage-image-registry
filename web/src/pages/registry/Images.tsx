import { useEffect, useRef, useState } from "react";
import { api, type GCResult, type ScanKind, type TransferView } from "../../api";
import { fmtBytes, useAction, useLoad } from "../../hooks";
import { useSession } from "../../session";
import { go } from "../../router";
import { useConfirm } from "../../components/dialog";
import { useToast } from "../../components/toast";
import { Alert, Progress } from "../../components/ui";
import { active } from "../../components/security";
import type { TabProps } from "../RegistryDetail";
import { AddImage } from "./AddImage";
import { RepoList } from "./RepoList";
import { RepoView } from "./RepoView";

/** The Images tab: a repository list, and one page per repository. Shared state (transfers, scans, maintenance) lives here. */
export function Images({ reg, repo }: TabProps & { repo?: string }) {
  const s = useSession();
  const confirm = useConfirm();
  const toast = useToast();
  const secOn = !!s.config?.security;
  const live = reg.state === "running";
  const [refresh, setRefresh] = useState(0); // bumped when a transfer ends, so open lists reload

  const summaries = useLoad(() => (live ? api.repoSummaries(reg.name) : Promise.resolve([])), [reg.name, live, refresh]);
  const [poll, setPoll] = useState(0);
  const scans = useLoad(() => (secOn && live ? api.scans(reg.name, "") : Promise.resolve([])), [reg.name, secOn, live, refresh], poll);
  const signing = useLoad(() => (secOn && live ? api.signing(reg.name) : Promise.resolve(null)), [reg.name, secOn, live]);
  // The list and the repository page share this data: reload it whenever the user moves between them.
  const first = useRef(true);
  useEffect(() => { if (first.current) { first.current = false; return; } summaries.reload(); }, [repo]); // eslint-disable-line react-hooks/exhaustive-deps
  const busyScans = (scans.data ?? []).some(active);
  useEffect(() => setPoll(busyScans ? 2500 : 0), [busyScans]);

  // add-image jobs
  const [adding, setAdding] = useState<{ repo?: string }>();
  const [dismissed, setDismissed] = useState<Set<string>>(new Set());
  const handled = useRef<Set<string>>(new Set());
  const [xferPoll, setXferPoll] = useState(0);
  const xfers = useLoad(() => (s.canOperate && live ? api.transfers(reg.name) : Promise.resolve([] as TransferView[])), [reg.name, s.canOperate, live], xferPoll);
  const activeXfers = (xfers.data ?? []).some((j) => j.status === "queued" || j.status === "running");
  useEffect(() => setXferPoll(activeXfers ? 1500 : 0), [activeXfers]);
  useEffect(() => {
    let changed = false;
    for (const j of xfers.data ?? []) if (j.status === "done" && !handled.current.has(j.id)) { handled.current.add(j.id); changed = true; }
    if (changed) setRefresh((n) => n + 1);
  }, [xfers.data]);
  // Running jobs always; a finished one only briefly (a success is announced by a toast too), a failure longer.
  const age = (j: TransferView) => Date.now() - new Date(j.finished || j.queued).getTime();
  const banner = (xfers.data ?? []).filter((j) => !dismissed.has(j.id) && (j.status === "queued" || j.status === "running" ||
    (j.status === "done" ? age(j) < 30_000 : age(j) < 120_000))).slice(0, 3);

  // maintenance and destructive actions
  const act = useAction();
  const [gcResult, setGcResult] = useState<GCResult>();
  const runGC = async () => {
    const ok = await confirm({
      title: "Free disk space?", confirmLabel: "Run garbage collection",
      body: <p>Removes layers and manifests that no tag refers to any more, for example after deleting images. The registry goes offline while it runs, then restarts by itself, so pushes and pulls in that window fail.</p>,
    });
    if (!ok) return;
    setGcResult(undefined);
    let res: GCResult | undefined;
    if (await act.run(async () => { res = await api.gc(reg.name); })) { setGcResult(res); toast.success("Garbage collection finished"); setRefresh((n) => n + 1); }
  };
  const deleteRepo = async (name: string, tags: number) => {
    const ok = await confirm({
      title: `Delete repository ${name}?`, danger: true, confirmLabel: "Delete repository", requireText: name,
      body: <p>Permanently removes <strong>{tags} {tags === 1 ? "tag" : "tags"}</strong> with their images, signatures and scan results. Disk space is reclaimed by garbage collection.</p>,
    });
    if (ok && await act.run(() => api.deleteRepo(reg.name, name))) {
      toast.success(`Deleted repository ${name}`);
      setRefresh((n) => n + 1);
      if (repo === name) go("registries", reg.name, "images");
    }
  };
  const runScans = async (r: string, ref: string, kinds: ScanKind[]) => { await api.startScan(reg.name, r, ref, kinds); await scans.reload(); };

  if (!live) return <Alert kind="info">{reg.state === "starting" ? "The registry is starting. Images will be available shortly." : "Start the registry to browse its images."}</Alert>;

  return (
    <>
      <Alert>{act.error ?? summaries.error}</Alert>
      {gcResult && (
        <div className="alert ok" role="status"><div style={{ flex: 1 }} className="num">
          Garbage collection done: {fmtBytes(gcResult.bytesBefore)} → {fmtBytes(gcResult.bytesAfter)}
          {gcResult.bytesBefore > gcResult.bytesAfter && ` (freed ${fmtBytes(gcResult.bytesBefore - gcResult.bytesAfter)})`}
        </div><button className="btn ghost sm" onClick={() => setGcResult(undefined)} aria-label="Dismiss">✕</button></div>
      )}
      {banner.map((j) => (
        <div key={j.id} className={`alert ${j.status === "failed" ? "error" : j.status === "done" ? "ok" : "info"}`} role={j.status === "failed" ? "alert" : "status"}>
          <div style={{ flex: 1, minWidth: 0 }} className="xfer">
            {j.status === "done" ? <span>{j.kind === "fix" ? "Fixed image pushed as" : j.kind === "rebase" ? "Rebased image pushed as" : "Added"} <strong>{j.repo}:{j.tag}</strong>{j.digest && <span className="muted mono"> · {j.digest.slice(0, 19)}…</span>}</span>
              : j.status === "failed" ? <span>Could not {j.kind === "fix" ? "fix" : j.kind === "rebase" ? "rebase" : "add"} <strong>{j.repo}:{j.tag}</strong>: {j.error}</span>
              : <>
                  <span>{j.status === "queued" ? "Waiting to " + (j.kind === "fix" ? "fix" : j.kind === "rebase" ? "rebase" : "add") : j.kind === "fix" ? "Fixing" : j.kind === "rebase" ? "Rebasing" : "Adding"} <strong>{j.repo}:{j.tag}</strong> <span className="muted">← {j.source}</span></span>
                  <Progress done={j.done} total={j.total} label={`${j.kind === "fix" ? "Fixing" : j.kind === "rebase" ? "Rebasing" : "Adding"} ${j.repo}:${j.tag}`} />
                  <span className="muted num">{j.total > 0 ? `${fmtBytes(j.done)} of ${fmtBytes(j.total)}` : j.kind === "fix" ? "Updating packages…" : "Reading the image…"}</span>
                </>}
          </div>
          {(j.status === "done" || j.status === "failed") && <button className="btn ghost sm" onClick={() => setDismissed((d) => new Set(d).add(j.id))} aria-label="Dismiss">✕</button>}
        </div>
      ))}

      {repo ? (
        <RepoView reg={reg} repo={repo} scans={scans.data ?? []} secOn={secOn} canOperate={s.canOperate} hasSigningKey={!!signing.data?.signingKey}
          refreshKey={refresh} reloadScans={scans.reload} runScans={runScans} onChanged={() => setRefresh((n) => n + 1)} onTransfer={() => xfers.reload()}
          onAdd={() => setAdding({ repo })} onDeleteRepo={deleteRepo} />
      ) : (
        <RepoList reg={reg} summaries={summaries.data} loading={summaries.loading} scans={scans.data ?? []} secOn={secOn} canOperate={s.canOperate}
          onAdd={() => setAdding({})} onDeleteRepo={deleteRepo} onGC={runGC} busy={act.busy} />
      )}

      {adding && (
        <AddImage reg={reg.name} repos={(summaries.data ?? []).map((r) => r.name)} secOn={secOn} defaultRepo={adding.repo}
          onClose={() => setAdding(undefined)} onStarted={() => xfers.reload()}
          onFinished={(j) => {
            toast.success(`Added ${j.repo}:${j.tag}`);
            const fromList = !adding.repo;
            setAdding(undefined); setRefresh((n) => n + 1); xfers.reload();
            if (fromList) go("registries", reg.name, "images", j.repo);
          }} />
      )}
    </>
  );
}
