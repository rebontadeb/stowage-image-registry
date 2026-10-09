import { useRef, useState } from "react";
import { api, type SCAPContent } from "../api";
import { fmtBytes, fmtDate, useAction, useLoad, useTitle } from "../hooks";
import { useConfirm } from "../components/dialog";
import { useToast } from "../components/toast";
import { Alert, Badge, Empty, Field, PageHead, Skeleton } from "../components/ui";

const PRESETS = [
  { name: "rhel-8", url: "https://security.access.redhat.com/data/oval/v2/RHEL8/rhel-8.oval.xml.bz2", label: "RHEL 8" },
  { name: "rhel-9", url: "https://security.access.redhat.com/data/oval/v2/RHEL9/rhel-9.oval.xml.bz2", label: "RHEL 9" },
  { name: "rhel-10", url: "https://security.access.redhat.com/data/oval/v2/RHEL10/rhel-10.oval.xml.bz2", label: "RHEL 10" },
];

export function SecurityTools() {
  useTitle("Security tools");
  const confirm = useConfirm();
  const toast = useToast();
  const st = useLoad(api.securityStatus, []);
  const act = useAction();
  const [name, setName] = useState("");
  const [url, setUrl] = useState("");
  const [upName, setUpName] = useState("");
  const file = useRef<HTMLInputElement>(null);
  const have = new Set((st.data?.content ?? []).map((c) => c.name));

  const addUrl = async (n: string, u: string) => {
    if (await act.run(() => api.addContentUrl(n, u))) { toast.success(`Imported ${n}`); setName(""); setUrl(""); st.reload(); }
  };
  const upload = async (e: React.FormEvent) => {
    e.preventDefault();
    const f = file.current?.files?.[0];
    if (!f) return;
    if (await act.run(() => api.uploadContent(upName, f))) { toast.success(`Uploaded ${upName}`); setUpName(""); if (file.current) file.current.value = ""; st.reload(); }
  };
  const remove = async (c: SCAPContent) => {
    const ok = await confirm({ title: `Delete ${c.name}?`, danger: true, confirmLabel: "Delete content", body: <p>OVAL checks of {c.name.replace("rhel-", "RHEL ")} images fail until content with this name is added again.</p> });
    if (ok && await act.run(() => api.deleteContent(c.name))) { toast.success(`Deleted ${c.name}`); st.reload(); }
  };

  return (
    <>
      <PageHead title="Security tools" subtitle="The scanners behind vulnerability, SBOM, signature and Red Hat OVAL checks." />
      <Alert>{st.error ?? act.error}</Alert>
      {st.loading && !st.data ? <div className="card"><Skeleton /></div> : !st.data?.enabled ? (
        <Alert kind="warn">Security scanning is disabled on this server (started with <code>-security=false</code>).</Alert>
      ) : (
        <>
          <section className="card" aria-labelledby="tools">
            <h2 id="tools">Scanners</h2>
            <p className="muted">Each scan runs one of these images as a short-lived container with minimal privileges. Registry credentials are passed in environment variables, never on a command line.</p>
            <dl className="kv">
              <dt>Vulnerabilities</dt><dd className="mono">{st.data.images.Grype}</dd>
              <dt>SBOM</dt><dd className="mono">{st.data.images.Syft}</dd>
              <dt>Signatures</dt><dd className="mono">{st.data.images.Cosign}</dd>
              <dt>Red Hat OVAL</dt><dd className="mono">{st.data.images.OpenSCAP}</dd>
              <dt>Parallel scans</dt><dd>{st.data.workers} <span className="muted">(vulnerability scans run one at a time)</span></dd>
            </dl>
          </section>

          <section className="card flush" aria-labelledby="oval">
            <div className="card-head"><h2 id="oval">OVAL content library</h2></div>
            <p className="muted" style={{ margin: "12px 18px 0" }}>
              Red Hat publishes machine-readable security advisories (OVAL). The OVAL check evaluates them against RHEL and UBI images using the content named <code>rhel-&lt;major version&gt;</code>.
              Content is downloaded over HTTPS or uploaded; nothing is fetched automatically.
            </p>
            {st.data.content.length === 0 ? <Empty title="No content yet">Import the content for the RHEL versions your tenants use.</Empty> : (
              <div className="table-wrap" tabIndex={0} role="region" aria-label="OVAL content"><table className="table stack" role="table">
                <caption className="sr-only">OVAL content</caption>
                <thead><tr role="row"><th scope="col">Name</th><th scope="col">File</th><th scope="col" className="r">Size</th><th scope="col" className="hide-sm">SHA-256</th><th scope="col" className="hide-sm">Added</th><th scope="col"><span className="sr-only">Actions</span></th></tr></thead>
                <tbody>{st.data.content.map((c) => (
                  <tr key={c.name} role="row">
                    <td role="cell" data-label="Name"><strong>{c.name}</strong></td><td role="cell" data-label="File" className="mono">{c.filename}</td><td role="cell" data-label="Size" className="r num">{fmtBytes(c.size)}</td>
                    <td role="cell" data-label="SHA-256" className="mono hide-sm" title={c.sha256}>{c.sha256.slice(0, 12)}…</td>
                    <td role="cell" data-label="Added" className="hide-sm muted">{fmtDate(c.added)}{c.addedBy ? ` · ${c.addedBy}` : ""}</td>
                    <td role="cell" data-label="" className="r"><button className="btn danger sm" onClick={() => remove(c)} disabled={act.busy} aria-label={`Delete ${c.name}`}>Delete</button></td>
                  </tr>))}</tbody>
              </table></div>
            )}
            <div style={{ padding: 18, borderTop: "1px solid var(--line)" }}>
              <h3 style={{ marginTop: 0 }}>Import from Red Hat</h3>
              <div className="row">
                {PRESETS.map((p) => <button key={p.name} className="btn secondary sm" disabled={act.busy} onClick={() => addUrl(p.name, p.url)}>{have.has(p.name) ? `Update ${p.label}` : `Import ${p.label}`}</button>)}
              </div>
              <h3>Import from another URL</h3>
              <form onSubmit={(e) => { e.preventDefault(); addUrl(name, url); }} className="row" style={{ alignItems: "flex-end" }}>
                <div style={{ width: 160 }}><Field label="Name" hint="e.g. rhel-9"><input className="input" value={name} onChange={(e) => setName(e.target.value)} required /></Field></div>
                <div style={{ flex: 1, minWidth: 260 }}><Field label="HTTPS URL" hint="Must end in a file name like rhel-9.oval.xml.bz2"><input className="input" type="url" value={url} onChange={(e) => setUrl(e.target.value)} required placeholder="https://" /></Field></div>
                <div style={{ marginBottom: 14 }}><button className="btn" disabled={act.busy}>{act.busy ? "Importing…" : "Import"}</button></div>
              </form>
              <h3>Upload a file</h3>
              <form onSubmit={upload} className="row" style={{ alignItems: "flex-end" }}>
                <div style={{ width: 160 }}><Field label="Name"><input className="input" value={upName} onChange={(e) => setUpName(e.target.value)} required /></Field></div>
                <div style={{ flex: 1, minWidth: 260 }}><Field label="OVAL file (.xml or .xml.bz2)"><input className="input" type="file" ref={file} accept=".xml,.bz2" required /></Field></div>
                <div style={{ marginBottom: 14 }}><button className="btn secondary" disabled={act.busy}>Upload</button></div>
              </form>
            </div>
          </section>
          <Alert kind="info">The OVAL check unpacks the image and needs the <Badge>CAP_SYS_CHROOT</Badge> capability, which restricted Kubernetes and OpenShift policies do not allow. It is available on podman only. Vulnerability scans, SBOMs and signatures work everywhere.</Alert>
        </>
      )}
    </>
  );
}
