import { useState } from "react";
import { api } from "../../api";
import { fmtDate, useAction, useLoad } from "../../hooks";
import { useSession } from "../../session";
import { useConfirm, Dialog } from "../../components/dialog";
import { useToast } from "../../components/toast";
import { Alert, Badge, Code, Empty, Field, Skeleton } from "../../components/ui";
import type { TabProps } from "../RegistryDetail";

/** Signing key and the public keys this registry trusts when verifying signatures. */
export function Security({ reg }: TabProps) {
  const s = useSession();
  const confirm = useConfirm();
  const toast = useToast();
  const info = useLoad(() => api.signing(reg.name), [reg.name]);
  const act = useAction();
  const [adding, setAdding] = useState(false);
  const sk = info.data?.signingKey;

  const create = async () => { if (await act.run(() => api.createSigningKey(reg.name))) { toast.success("Signing key created"); info.reload(); } };
  const removeKey = async () => {
    const ok = await confirm({ title: "Delete the signing key?", danger: true, confirmLabel: "Delete private key", body: (
      <p>The private key is destroyed and this registry can no longer sign images. Existing signatures keep verifying because the public key stays trusted. Remove it from the trusted keys as well if it was compromised.</p>) });
    if (ok && await act.run(() => api.deleteSigningKey(reg.name))) { toast.success("Signing key deleted"); info.reload(); }
  };
  const removeTrusted = async (id: number, label: string) => {
    const ok = await confirm({ title: `Stop trusting ${label}?`, danger: true, confirmLabel: "Remove key", body: <p>Images signed only with this key will show as not trusted.</p> });
    if (ok && await act.run(() => api.removeTrustKey(reg.name, id))) { toast.success("Key removed"); info.reload(); }
  };

  return (
    <>
      <Alert>{info.error ?? act.error}</Alert>
      <section className="card" aria-labelledby="sk">
        <h2 id="sk">Signing key</h2>
        {info.loading && !info.data ? <Skeleton rows={2} /> : sk ? (
          <>
            <dl className="kv">
              <dt>Fingerprint</dt><dd className="mono">{sk.fingerprint}</dd>
              <dt>Created</dt><dd>{fmtDate(sk.created)}</dd>
              <dt>Private key</dt><dd>Stored encrypted on the manager. It never leaves it and is never shown.</dd>
            </dl>
            <h3>Public key</h3>
            <Code>{sk.publicKey.trim()}</Code>
            <p className="muted">Give this to anyone who verifies your images:</p>
            <Code>{`cosign verify --key cosign.pub ${reg.host || "<registry>"}/<repo>:<tag>`}</Code>
            {s.isAdmin && <button className="btn danger" disabled={act.busy} onClick={removeKey}>Delete private key…</button>}
          </>
        ) : (
          <>
            <p className="muted">This registry has no signing key, so images cannot be signed from the manager. Signing proves an image came from you and was not changed afterwards.</p>
            {s.isAdmin ? <button className="btn" disabled={act.busy} onClick={create}>{act.busy ? "Creating…" : "Create signing key"}</button> : <p className="muted">An administrator can create one.</p>}
          </>
        )}
      </section>

      <section className="card flush" aria-labelledby="tk">
        <div className="card-head"><h2 id="tk">Trusted keys</h2><span className="spacer" />{s.canOperate && <button className="btn secondary sm" onClick={() => setAdding(true)}>Add trusted key</button>}</div>
        <p className="muted" style={{ margin: "12px 18px 0" }}>An image counts as signed only when one of these public keys verifies its signature.</p>
        {info.loading && !info.data ? <Skeleton rows={2} /> : info.data?.trustedKeys.length === 0 ? (
          <Empty title="No trusted keys">Signatures can be detected but not verified until you add the signer's public key{sk ? "" : ", or create a signing key above"}.</Empty>
        ) : (
          <ul className="plain" style={{ padding: "4px 18px" }}>
            {info.data?.trustedKeys.map((k) => (
              <li key={k.id}>
                <div style={{ minWidth: 0 }}><strong>{k.label}</strong> {k.own && <Badge tone="info">this registry's key</Badge>}<div className="mono muted" style={{ fontSize: 12 }}>{k.fingerprint}</div></div>
                <span className="spacer" />
                {s.canOperate && <button className="btn danger sm" disabled={act.busy} onClick={() => removeTrusted(k.id, k.label)} aria-label={`Remove trusted key ${k.label}`}>Remove</button>}
              </li>
            ))}
          </ul>
        )}
      </section>
      {adding && <AddKey reg={reg.name} onClose={() => setAdding(false)} onDone={() => { setAdding(false); toast.success("Key added"); info.reload(); }} />}
    </>
  );
}

function AddKey({ reg, onClose, onDone }: { reg: string; onClose: () => void; onDone: () => void }) {
  const [label, setLabel] = useState("");
  const [pem, setPem] = useState("");
  const act = useAction();
  const submit = async (e: React.FormEvent) => { e.preventDefault(); if (await act.run(() => api.addTrustKey(reg, label, pem))) onDone(); };
  return (
    <Dialog title="Add trusted key" onClose={onClose} dismissible={!act.busy} footer={
      <><button className="btn secondary" onClick={onClose} disabled={act.busy}>Cancel</button><button className="btn" form="tk-form" disabled={act.busy}>{act.busy ? "Adding…" : "Add key"}</button></>
    }>
      <form id="tk-form" onSubmit={submit}>
        <Field label="Name" hint="Shown next to signed images, e.g. Release pipeline."><input className="input" data-autofocus value={label} onChange={(e) => setLabel(e.target.value)} required maxLength={64} /></Field>
        <Field label="Public key (PEM)" hint="The contents of cosign.pub: an ECDSA P-256 public key."><textarea className="input" value={pem} onChange={(e) => setPem(e.target.value)} placeholder="-----BEGIN PUBLIC KEY-----" required spellCheck={false} /></Field>
        <Alert>{act.error}</Alert>
      </form>
    </Dialog>
  );
}
