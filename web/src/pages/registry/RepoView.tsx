import { useMemo, useState } from "react";
import { api, type Reg, type ScanKind, type ScanView, type SigState, type VulnSummary } from "../../api";
import { useAction, useLoad } from "../../hooks";
import { href } from "../../router";
import { useConfirm } from "../../components/dialog";
import { useToast } from "../../components/toast";
import { Menu, type MenuItem } from "../../components/Menu";
import { Alert, Badge, Empty, Skeleton } from "../../components/ui";
import { SigBadge, VulnCounts, Working, active, find } from "../../components/security";
import { ScanDialog } from "./ScanDialog";
import { RebaseDialog } from "./RebaseDialog";

/** One repository: its tags with security status, and the actions for them. */
export function RepoView({ reg, repo, scans, secOn, canOperate, hasSigningKey, refreshKey, reloadScans, runScans, onChanged, onTransfer, onAdd, onDeleteRepo }: {
  reg: Reg; repo: string; scans: ScanView[]; secOn: boolean; canOperate: boolean; hasSigningKey: boolean; refreshKey: number;
  reloadScans: () => Promise<void>; runScans: (repo: string, ref: string, kinds: ScanKind[]) => Promise<void>;
  onChanged: () => void; onTransfer: () => void; onAdd: () => void; onDeleteRepo: (name: string, tags: number) => void;
}) {
  const confirm = useConfirm();
  const toast = useToast();
  const tags = useLoad(() => api.tags(reg.name, repo), [reg.name, repo, refreshKey]);
  const act = useAction();
  const [rebase, setRebase] = useState<string>();
  const [detail, setDetail] = useState<{ tag: string; digest: string }>();
  const images = useMemo(() => (tags.data ?? []).filter((t) => t.kind === "image"), [tags.data]);
  const hiddenSigs = (tags.data ?? []).length - images.length;
  const repoScans = useMemo(() => scans.filter((x) => x.repo === repo), [scans, repo]);

  const host = reg.host || `127.0.0.1:${reg.hostPort}`;
  const copyName = async (tag: string) => {
    const full = `${host}/${repo}:${tag}`;
    // The async clipboard API needs a secure context and permission; the older selection-based copy does not.
    const legacy = () => {
      const ta = document.createElement("textarea");
      ta.value = full; ta.setAttribute("readonly", ""); ta.style.position = "fixed"; ta.style.opacity = "0";
      document.body.appendChild(ta); ta.select();
      try { return document.execCommand("copy"); } finally { ta.remove(); }
    };
    let ok = false;
    try { await navigator.clipboard.writeText(full); ok = true; } catch { ok = legacy(); }
    if (ok) toast.success(`Copied ${full}`); else toast.error(`Could not copy. Select it by hand: ${full}`);
  };

  const deleteTag = async (tag: string, digest: string) => {
    const same = images.filter((t) => t.digest === digest).map((t) => t.tag);
    const ok = await confirm({
      title: `Delete ${repo}:${tag}?`, danger: true, confirmLabel: "Delete image",
      body: same.length > 1
        ? <p>These tags all point to the same image and <strong>will all be removed</strong>: {same.map((t) => <code key={t}>{t} </code>)}</p>
        : <p>The image, its signature and its stored scan results are removed. Disk space is reclaimed by garbage collection.</p>,
    });
    if (ok && await act.run(() => api.deleteTag(reg.name, repo, tag))) { toast.success(`Deleted ${repo}:${tag}`); tags.reload(); reloadScans(); onChanged(); }
  };
  const scanOne = async (digest: string) => { if (await act.run(() => runScans(repo, digest, ["vuln", "sbom", "sig"]))) toast.success("Scan started"); };
  const scanAll = async () => {
    const uniq = [...new Set(images.map((t) => t.digest))];
    if (await act.run(async () => { for (const d of uniq) await runScans(repo, d, ["vuln", "sbom", "sig"]); })) toast.success(`Scanning ${uniq.length} image${uniq.length === 1 ? "" : "s"}`);
  };
  const sign = async (digest: string, tag: string) => {
    const ok = await confirm({ title: `Sign ${repo}:${tag}?`, confirmLabel: "Sign image", body: <p>Signs this exact image (<code>{digest.slice(0, 19)}…</code>) with the registry's signing key. The action is recorded in the audit log.</p> });
    if (ok && await act.run(async () => { await api.sign(reg.name, repo, digest); await reloadScans(); })) toast.success(`Signed ${repo}:${tag}`);
  };

  const fix = async (tag: string) => {
    let plan;
    if (!(await act.run(async () => { plan = await api.fixPlan(reg.name, repo, tag); }))) return;
    const p = plan as unknown as { packages: string[]; all: boolean; manager: "dnf" | "apk"; newTag: string };
    const repos = p.manager === "apk" ? "Alpine" : "Red Hat";
    const ok = await confirm({
      title: `Fix ${repo}:${tag}?`, confirmLabel: "Build fixed image",
      body: (
        <>
          <p>Builds a patched copy of this image and pushes it as <strong>{repo}:{p.newTag}</strong>. <strong>{repo}:{tag}</strong> is not changed. The new image is scanned when it is ready.</p>
          {p.all
            ? <p>The scan names no individually fixable package, so <strong>every package that has an update</strong> in the {repos} repositories is upgraded.</p>
            : <p>Upgrades {p.packages.length} package{p.packages.length === 1 ? "" : "s"}: {p.packages.slice(0, 12).map((x) => <code key={x}>{x} </code>)}{p.packages.length > 12 && `and ${p.packages.length - 12} more`}.</p>}
          <p className="muted">Only operating-system packages of RHEL/UBI and Alpine images are patched. Findings in application dependencies, or advisories that have no fix yet, stay; compare the new scan to see what changed.</p>
        </>
      ),
    });
    if (ok && await act.run(async () => { await api.fixImage(reg.name, repo, tag); })) { toast.success(`Building ${repo}:${p.newTag}`); onTransfer(); }
  };

  const vulnCell = (digest: string) => {
    const v = find(repoScans, digest, "vuln");
    if (!v) return <span className="muted">Not scanned</span>;
    if (active(v)) return <Working what="Scanning" />;
    if (v.status === "failed") return <span title={v.error}><Badge tone="bad">Scan failed</Badge></span>;
    return <VulnCounts s={v.summary as unknown as VulnSummary} levels={["critical", "high", "medium"]} />;
  };
  const sigCell = (digest: string) => {
    const v = find(repoScans, digest, "sig");
    if (!v) return <span className="muted">—</span>;
    if (active(v)) return <Working what="Checking" />;
    if (v.status === "failed") return <span title={v.error}><Badge tone="bad">Check failed</Badge></span>;
    const sum = v.summary as { status: SigState; key?: string };
    return <span title={sum.key ? `Signed by ${sum.key}` : undefined}><SigBadge status={sum.status} /></span>;
  };

  const repoMenu: MenuItem[] = [
    ...(secOn && images.length > 0 ? [{ label: "Scan all tags", onSelect: scanAll, disabled: act.busy }] : []),
    { label: "Delete repository…", onSelect: () => onDeleteRepo(repo, images.length), danger: true },
  ];

  return (
    <>
      <div className="crumbs-row">
        <a className="btn ghost sm" href={href("registries", reg.name, "images")}>‹ Repositories</a>
        <h2 className="repo-name" style={{ margin: 0, fontSize: 17 }}>{repo}</h2>
        <span className="spacer" />
        {canOperate && <button className="btn" onClick={onAdd}>Add image</button>}
        {canOperate && <Menu label="Repository actions" items={repoMenu} />}
      </div>
      <Alert>{tags.error ?? act.error}</Alert>

      <div className="card flush">
        {tags.loading && !tags.data ? <Skeleton rows={3} /> : images.length === 0 ? (
          <Empty title="No tags in this repository" action={<a className="btn secondary" href={href("registries", reg.name, "images")}>Back to repositories</a>}>
            It may have been deleted or emptied. Empty repositories are not listed.
          </Empty>
        ) : (
          <div className="table-wrap" tabIndex={0} role="region" aria-label={`Tags in ${repo}`}>
            <table className="table stack roomy" role="table">
              <caption className="sr-only">Tags in {repo}</caption>
              <thead>
                <tr role="row">
                  <th scope="col" role="columnheader">Tag</th>
                  {secOn && <><th scope="col" role="columnheader">Vulnerabilities</th><th scope="col" role="columnheader">Signature</th></>}
                  <th scope="col" role="columnheader"><span className="sr-only">Actions</span></th>
                </tr>
              </thead>
              <tbody>
                {images.map((t) => {
                  const vs = find(repoScans, t.digest, "vuln");
                  const canFix = secOn && canOperate && vs?.status === "done" && ((vs.summary as unknown as VulnSummary).total ?? 0) > 0;
                  const working = active(find(repoScans, t.digest, "vuln")) || active(find(repoScans, t.digest, "sig"));
                  return (
                    <tr key={t.tag} role="row">
                      <td role="cell" data-label="Tag"><span><span className="repo-name">{t.tag}</span> <span className="muted mono" title={t.digest}>{t.digest.slice(7, 19)}</span></span></td>
                      {secOn && <><td role="cell" data-label="Vulnerabilities">{vulnCell(t.digest)}</td><td role="cell" data-label="Signature">{sigCell(t.digest)}</td></>}
                      <td role="cell" data-label="" className="r">
                        <span className="row end" style={{ gap: 6, flexWrap: "wrap", justifyContent: "flex-end" }}>
                          <button className="btn secondary sm" onClick={() => copyName(t.tag)} aria-label={`Copy image name ${host}/${repo}:${t.tag}`} title={`${host}/${repo}:${t.tag}`}>Copy</button>
                          {secOn && <button className="btn secondary sm" onClick={() => setDetail({ tag: t.tag, digest: t.digest })} aria-label={`Security details for ${repo}:${t.tag}`}>Details</button>}
                          {secOn && canOperate && <button className="btn secondary sm" onClick={() => scanOne(t.digest)} disabled={act.busy || working}>Scan image</button>}
                          {secOn && canOperate && hasSigningKey && <button className="btn secondary sm" onClick={() => sign(t.digest, t.tag)} disabled={act.busy}>Sign image</button>}
                          {canFix && <button className="btn secondary sm" onClick={() => fix(t.tag)} disabled={act.busy || working}>Fix</button>}
                          {canOperate && <button className="btn secondary sm" onClick={() => setRebase(t.tag)} disabled={act.busy}>Rebase</button>}
                          {canOperate && <button className="btn danger sm" onClick={() => deleteTag(t.tag, t.digest)} disabled={act.busy}>Delete tag</button>}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
      {hiddenSigs > 0 && <p className="muted" style={{ marginTop: 10 }}>{hiddenSigs} signature tag{hiddenSigs === 1 ? "" : "s"} hidden. They belong to the images above and are removed with them.</p>}

      {detail && (
        <ScanDialog reg={reg.name} repo={repo} tag={detail.tag} digest={detail.digest} scans={repoScans} canOperate={canOperate}
          hasSigningKey={hasSigningKey} onClose={() => setDetail(undefined)}
          onRun={(kinds) => runScans(repo, detail.digest, kinds)}
          onSign={async () => { await api.sign(reg.name, repo, detail.digest); await reloadScans(); toast.success(`Signed ${repo}:${detail.tag}`); }} />
      )}
      {rebase && <RebaseDialog reg={reg.name} repo={repo} tag={rebase} onClose={() => setRebase(undefined)} onStarted={onTransfer} />}
    </>
  );
}
