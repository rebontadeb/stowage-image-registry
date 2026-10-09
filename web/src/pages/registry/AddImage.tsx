import { useEffect, useRef, useState } from "react";
import { api, type TransferView } from "../../api";
import { fmtBytes, useAction } from "../../hooks";
import { Dialog } from "../../components/dialog";
import { Alert, Code, Field, Progress } from "../../components/ui";

type Mode = "import" | "upload";

const REPO_RE = /^[a-z0-9]+([._-][a-z0-9]+)*(\/[a-z0-9]+([._-][a-z0-9]+)*)*$/;
const TAG_RE = /^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$/;

/** "docker.io/library/alpine:3.19" -> repo "alpine", tag "3.19" (registry host and Docker Hub's library/ dropped). */
export function suggestFromSource(src: string): { repo: string; tag: string } {
  let s = src.trim();
  let tag = "latest";
  const at = s.indexOf("@");
  if (at >= 0) s = s.slice(0, at);
  const colon = s.lastIndexOf(":");
  if (colon > s.lastIndexOf("/")) { tag = s.slice(colon + 1) || "latest"; s = s.slice(0, colon); }
  const parts = s.split("/").filter(Boolean);
  if (parts.length > 1 && (parts[0].includes(".") || parts[0].includes(":") || parts[0] === "localhost")) parts.shift();
  if (parts[0] === "library") parts.shift();
  return { repo: parts.join("/").toLowerCase(), tag };
}

function suggestFromFile(name: string): { repo: string; tag: string } {
  const base = name.replace(/\.(tar\.gz|tgz|tar)$/i, "").toLowerCase().replace(/[^a-z0-9._/-]+/g, "-").replace(/^[-._/]+|[-._/]+$/g, "");
  return { repo: base, tag: "latest" };
}

export function AddImage({ reg, repos, secOn, defaultRepo, onClose, onStarted, onFinished }: {
  reg: string; repos: string[]; secOn: boolean; defaultRepo?: string; onClose: () => void;
  onStarted: () => void; onFinished: (j: TransferView) => void;
}) {
  const [mode, setMode] = useState<Mode>("import");
  const [source, setSource] = useState("");
  const [user, setUser] = useState("");
  const [pass, setPass] = useState("");
  const [skipTLS, setSkipTLS] = useState(false);
  const [allPlat, setAllPlat] = useState(false);
  const [file, setFile] = useState<File>();
  const [repo, setRepo] = useState(defaultRepo ?? "");
  const [tag, setTag] = useState("latest");
  const [touched, setTouched] = useState({ repo: !!defaultRepo, tag: false });
  const [overwrite, setOverwrite] = useState(false);
  const [scan, setScan] = useState(secOn);
  const act = useAction();
  const [sent, setSent] = useState<{ sent: number; total: number }>();
  const [job, setJob] = useState<TransferView>();
  const fileInput = useRef<HTMLInputElement>(null);

  // Suggest the destination from the source until the user types their own.
  useEffect(() => {
    const s = mode === "import" ? suggestFromSource(source) : file ? suggestFromFile(file.name) : { repo: "", tag: "latest" };
    if (!touched.repo) setRepo(s.repo);
    if (!touched.tag) setTag(s.tag);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [source, file, mode]);

  // After the request is accepted, follow the job until it ends.
  useEffect(() => {
    if (!job || job.status === "done" || job.status === "failed") return;
    const t = setInterval(async () => {
      try {
        const j = (await api.transfers(reg)).find((x) => x.id === job.id);
        if (j) setJob(j);
      } catch { /* keep trying; the banner on the page also follows the job */ }
    }, 1000);
    return () => clearInterval(t);
  }, [job, reg]);
  useEffect(() => { if (job?.status === "done") onFinished(job); }, [job?.status]); // eslint-disable-line react-hooks/exhaustive-deps

  const repoOk = repo === "" || REPO_RE.test(repo);
  const tagOk = tag === "" || TAG_RE.test(tag);
  const exists = repos.includes(repo);
  const ready = repo !== "" && tag !== "" && repoOk && tagOk && (mode === "import" ? source.trim() !== "" : !!file);
  const running = job && (job.status === "queued" || job.status === "running");

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setJob(undefined); setSent(undefined);
    const ok = await act.run(async () => {
      const started = mode === "import"
        ? await api.importImage(reg, { source: source.trim(), username: user || undefined, password: pass || undefined, skipTLS, allPlatforms: allPlat, repo, tag, overwrite, scan })
        : await api.uploadImage(reg, file!, { repo, tag, overwrite, scan }, (s, total) => setSent({ sent: s, total }));
      setJob(started);
      onStarted();
    });
    if (!ok) setSent(undefined);
  };

  const failed = job?.status === "failed";
  const title = running ? "Adding image…" : "Add image";
  const footer = running ? (
    <><button className="btn secondary" onClick={onClose}>Continue in background</button></>
  ) : (
    <>
      <button type="button" className="btn secondary" onClick={onClose} disabled={act.busy}>{failed ? "Close" : "Cancel"}</button>
      <button className="btn" form="add-image" disabled={!ready || act.busy}>{act.busy ? "Starting…" : failed ? "Try again" : mode === "import" ? "Copy image" : "Upload image"}</button>
    </>
  );

  return (
    <Dialog title={title} onClose={onClose} wide footer={footer} dismissible={!act.busy}>
      {running || (job && job.status === "done") ? (
        <div className="xfer" role="status" aria-live="polite">
          <div><strong>{job!.repo}:{job!.tag}</strong> <span className="muted">← {job!.source}</span></div>
          <Progress done={job!.done} total={job!.total} label="Transfer progress" />
          <div className="muted num">
            {job!.status === "queued" ? "Waiting for a free slot…" : job!.total > 0 ? `${fmtBytes(job!.done)} of ${fmtBytes(job!.total)}` : "Reading the image…"}
          </div>
          <p className="muted" style={{ margin: 0 }}>You can close this window; the transfer keeps running and its progress stays on the Images tab.</p>
        </div>
      ) : (
        <form id="add-image" onSubmit={submit}>
          <div className="tabs inner" role="tablist" aria-label="How to add the image">
            <button type="button" role="tab" aria-selected={mode === "import"} onClick={() => setMode("import")}>From a registry</button>
            <button type="button" role="tab" aria-selected={mode === "upload"} onClick={() => setMode("upload")}>Upload a file</button>
          </div>

          {mode === "import" ? (
            <>
              <Field label="Source image" hint="Any registry: docker.io/library/alpine:3.19, quay.io/org/app:v1, registry.access.redhat.com/ubi9/ubi-micro:latest">
                <input className="input mono" data-autofocus value={source} onChange={(e) => setSource(e.target.value)} placeholder="docker.io/library/alpine:3.19" spellCheck={false} autoComplete="off" required />
              </Field>
              <details className="more">
                <summary>Private source or other options</summary>
                <Field label="Username" hint="Only needed when the source requires a login."><input className="input" value={user} onChange={(e) => setUser(e.target.value)} autoComplete="off" /></Field>
                <Field label="Password or access token"><input className="input" type="password" value={pass} onChange={(e) => setPass(e.target.value)} autoComplete="new-password" /></Field>
                <label className="check"><input type="checkbox" checked={skipTLS} onChange={(e) => setSkipTLS(e.target.checked)} /> Source uses a self-signed certificate</label>
                <label className="check"><input type="checkbox" checked={allPlat} onChange={(e) => setAllPlat(e.target.checked)} /> Copy every architecture (default: only this server's)</label>
                <p className="muted" style={{ margin: "6px 0 0" }}>Credentials are used for this copy only and are never stored or logged.</p>
              </details>
            </>
          ) : (
            <>
              <Field label="Image archive" hint="A docker-archive file (.tar or .tar.gz), created on your machine with:">
                <input ref={fileInput} className="input" type="file" accept=".tar,.tar.gz,.tgz,application/x-tar,application/gzip" onChange={(e) => setFile(e.target.files?.[0])} required />
              </Field>
              <Code>{"podman save -o myapp.tar myapp:1.0"}</Code>
              <p className="muted">One image per file. OCI-format archives are not supported; <code>docker save</code> works too.</p>
            </>
          )}

          <div className="grid" style={{ gridTemplateColumns: "2fr 1fr", gap: "0 12px" }}>
            <Field label="Repository in this registry" error={repoOk ? undefined : "Lowercase letters, digits, . _ - and / between parts."}>
              <input className="input mono" list="known-repos" value={repo} onChange={(e) => { setRepo(e.target.value.toLowerCase()); setTouched((t) => ({ ...t, repo: true })); }} aria-invalid={!repoOk} required spellCheck={false} />
              <datalist id="known-repos">{repos.map((r) => <option key={r} value={r} />)}</datalist>
            </Field>
            <Field label="Tag" error={tagOk ? undefined : "Letters, digits, . _ -"}>
              <input className="input mono" value={tag} onChange={(e) => { setTag(e.target.value); setTouched((t) => ({ ...t, tag: true })); }} aria-invalid={!tagOk} required spellCheck={false} />
            </Field>
          </div>
          {exists && <p className="muted" style={{ marginTop: -6 }}>Adds to the existing repository <code>{repo}</code>.</p>}
          <label className="check"><input type="checkbox" checked={overwrite} onChange={(e) => setOverwrite(e.target.checked)} /> Replace the tag if it already exists</label>
          {secOn && <label className="check"><input type="checkbox" checked={scan} onChange={(e) => setScan(e.target.checked)} /> Scan for vulnerabilities when it has been added</label>}

          {act.busy && sent && (
            <div className="xfer" style={{ marginTop: 12 }} role="status" aria-live="polite">
              <Progress done={sent.sent} total={sent.total} label="Upload progress" />
              <div className="muted num">Uploading {fmtBytes(sent.sent)} of {fmtBytes(sent.total)}</div>
            </div>
          )}
          <Alert>{act.error ?? (failed ? job?.error : undefined)}</Alert>
        </form>
      )}
    </Dialog>
  );
}
