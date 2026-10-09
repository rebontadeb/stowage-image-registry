import { useState } from "react";
import { api } from "../../api";
import { useAction } from "../../hooks";
import { Dialog } from "../../components/dialog";
import { Alert, Field } from "../../components/ui";

const TAG_RE = /^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$/;

/** Moves an image onto a newer base image: the image's own layers are kept, the base layers are swapped. */
export function RebaseDialog({ reg, repo, tag, onClose, onStarted }: {
  reg: string; repo: string; tag: string; onClose: () => void; onStarted: () => void;
}) {
  const [oldBase, setOldBase] = useState("");
  const [newBase, setNewBase] = useState("");
  const [newTag, setNewTag] = useState(`${tag}-rebased`);
  const [user, setUser] = useState("");
  const [pass, setPass] = useState("");
  const [skipTLS, setSkipTLS] = useState(false);
  const act = useAction();
  const check = useAction();
  const [checked, setChecked] = useState<{ base: string; matches: boolean; baseLayers: number; imageLayers: number; common: number; history: string[] }>();
  const [layers, setLayers] = useState("");
  const tagOk = TAG_RE.test(newTag) && newTag !== tag;
  const nLayers = layers.trim() === "" ? 0 : Number(layers);
  const layersOk = layers.trim() === "" || (Number.isInteger(nLayers) && nLayers >= 1 && nLayers <= 200);
  const ready = (oldBase.trim() !== "" || nLayers > 0) && layersOk && newBase.trim() !== "" && oldBase.trim() !== newBase.trim() && tagOk;

  const runCheck = async () => {
    const base = oldBase.trim();
    let res: Awaited<ReturnType<typeof api.rebaseCheck>> | undefined;
    if (await check.run(async () => { res = await api.rebaseCheck(reg, { repo, ref: tag, oldBase: base, username: user || undefined, password: pass || undefined, skipTLS }); })) setChecked({ base, ...res! });
  };

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (await act.run(() => api.rebaseImage(reg, { repo, ref: tag, oldBase: oldBase.trim(), baseLayers: nLayers || undefined, newBase: newBase.trim(), tag: newTag,
      username: user || undefined, password: pass || undefined, skipTLS }))) { onStarted(); onClose(); }
  };

  return (
    <Dialog title={`Rebase ${repo}:${tag}`} onClose={onClose} wide dismissible={!act.busy}
      footer={<>
        <button type="button" className="btn secondary" onClick={onClose} disabled={act.busy}>Cancel</button>
        <button className="btn" form="rebase" disabled={!ready || act.busy}>{act.busy ? "Starting…" : "Build rebased image"}</button>
      </>}>
      <form id="rebase" onSubmit={submit}>
        <p>Builds a copy of this image that sits on a newer base image and pushes it as <strong>{repo}:{newTag || "…"}</strong>. <strong>{repo}:{tag}</strong> is not changed, and the new image is scanned when it is ready.</p>
        <Field label="Base it was built on" hint="The image named in the FROM line of its Dockerfile, e.g. docker.io/library/nginx:1.21.4-alpine. Stowage checks that the image really starts with that image's layers.">
          <input className="input mono" data-autofocus value={oldBase} onChange={(e) => { setOldBase(e.target.value); setChecked(undefined); }} placeholder="docker.io/library/nginx:1.21.4-alpine" spellCheck={false} autoComplete="off" />
          <div className="row" style={{ marginTop: 6 }}>
            <button type="button" className="btn secondary sm" onClick={runCheck} disabled={oldBase.trim() === "" || check.busy}>{check.busy ? "Checking…" : "Check"}</button>
            {checked && checked.base === oldBase.trim() && (
              <span role="status" className={checked.matches ? "ok-text" : "err-text"}>
                {checked.matches ? `Yes: this image is built on it (${checked.baseLayers} of ${checked.imageLayers} layers are the base).`
                  : `No: only ${checked.common} of that base's ${checked.baseLayers} layers match. Its tag may have been rebuilt since this image was made; use "Layers that belong to the base" below.`}
              </span>
            )}
          </div>
          {checked && checked.base === oldBase.trim() && (
            <details className="more">
              <summary>How this image was built ({checked.imageLayers} layers)</summary>
              <pre className="mono" style={{ fontSize: 12, whiteSpace: "pre-wrap", wordBreak: "break-word", margin: "6px 0 0" }}>{checked.history.join("\n")}</pre>
              <p className="muted" style={{ margin: "6px 0 0" }}>Lines starting with # create a layer. The base is the first block of layers, typically everything up to your own COPY or RUN steps.</p>
            </details>
          )}
          {check.error && <span role="alert" className="err-text">{check.error}</span>}
        </Field>
        <Field label="Layers that belong to the base (optional)" hint="Use this when the check says the base does not match: enter how many of the image's first layers are the base, from the build steps above. Replaces the check against the old base."
          error={layersOk ? undefined : "A whole number from 1 to 200."}>
          <input className="input" inputMode="numeric" value={layers} onChange={(e) => setLayers(e.target.value)} aria-invalid={!layersOk} placeholder="e.g. 6" style={{ maxWidth: 120 }} />
        </Field>
        <Field label="New base" hint="A newer image of the same kind, e.g. docker.io/library/nginx:1.27-alpine.">
          <input className="input mono" value={newBase} onChange={(e) => setNewBase(e.target.value)} placeholder="docker.io/library/nginx:1.27-alpine" spellCheck={false} autoComplete="off" required />
        </Field>
        <Field label="New tag" error={newTag !== "" && !tagOk ? (newTag === tag ? "Use a different tag than the original." : "Letters, digits, . _ -") : undefined}>
          <input className="input mono" value={newTag} onChange={(e) => setNewTag(e.target.value)} aria-invalid={!tagOk} spellCheck={false} required />
        </Field>
        <details className="more">
          <summary>Private base images</summary>
          <Field label="Username"><input className="input" value={user} onChange={(e) => setUser(e.target.value)} autoComplete="off" /></Field>
          <Field label="Password or access token"><input className="input" type="password" value={pass} onChange={(e) => setPass(e.target.value)} autoComplete="new-password" /></Field>
          <label className="check"><input type="checkbox" checked={skipTLS} onChange={(e) => setSkipTLS(e.target.checked)} /> Registry uses a self-signed certificate</label>
          <p className="muted" style={{ margin: "6px 0 0" }}>Used for this rebase only; never stored or logged.</p>
        </details>
        <Alert kind="warn">
          <span><strong>Not for Python, Node, Java or other language images.</strong> If your own layers ran <code>pip install</code>, <code>npm install</code> or similar, those packages are tied to the old runtime version (for example <code>python3.9/site-packages</code>) and will not work on a newer one; the container fails to start. For those images, change <code>FROM</code> in your Dockerfile, rebuild and push. Rebase suits images that only add files or configuration to an OS or server base, such as nginx.</span>
        </Alert>
        <p className="muted">Your application layers are carried over unchanged, with the image's user, command and environment. Check that the new image still starts: a base that is far newer can break an application. Variables set by the old base (for example a version number) keep their old values.</p>
        <Alert>{act.error}</Alert>
      </form>
    </Dialog>
  );
}
