import { useState } from "react";
import { api } from "../../api";
import { fmtDate, useAction, useLoad } from "../../hooks";
import { useSession } from "../../session";
import { useConfirm } from "../../components/dialog";
import { useToast } from "../../components/toast";
import { Alert, Badge, Field } from "../../components/ui";
import type { TabProps } from "../RegistryDetail";

export function Tls({ reg, reload }: TabProps) {
  const s = useSession();
  const confirm = useConfirm();
  const toast = useToast();
  const info = useLoad(() => api.tls(reg.name), [reg.name, reg.tls]);
  const [hosts, setHosts] = useState("");
  const [cert, setCert] = useState("");
  const [key, setKey] = useState("");
  const act = useAction();
  const t = info.data;

  const apply = async (fn: () => Promise<unknown>, msg: string) => {
    if (await act.run(fn)) { toast.success(msg); info.reload(); reload(); }
  };
  const disable = async () => {
    const ok = await confirm({ title: "Disable HTTPS?", danger: true, confirmLabel: "Disable HTTPS",
      body: <p>The registry goes back to plain HTTP. Passwords and images will travel unencrypted.</p> });
    if (ok) apply(() => api.removeTLS(reg.name), "HTTPS disabled");
  };

  return (
    <>
      <section className="card" aria-labelledby="https">
        <div className="row"><h2 id="https" style={{ margin: 0 }}>HTTPS</h2>{t && (t.enabled ? <Badge tone="ok">Enabled</Badge> : <Badge tone="warn">Disabled</Badge>)}</div>
        <Alert>{info.error ?? act.error}</Alert>
        {t?.enabled ? (
          <>
            <dl className="kv" style={{ marginTop: 12 }}>
              <dt>Certificate</dt><dd>{t.selfSigned ? "Self-signed" : "Provided"}</dd>
              <dt>Expires</dt><dd>{fmtDate(t.notAfter)}</dd>
              <dt>Names</dt><dd>{t.dnsNames?.join(", ") || "—"}</dd>
            </dl>
            {s.canOperate && <button className="btn danger" style={{ marginTop: 12 }} disabled={act.busy} onClick={disable}>Disable HTTPS…</button>}
          </>
        ) : <p className="muted" style={{ marginTop: 12 }}>Traffic and passwords travel unencrypted.</p>}
      </section>

      {s.canOperate && (
        <>
          <section className="card" aria-labelledby="gen">
            <h2 id="gen">Generate a self-signed certificate</h2>
            <Field label="Extra host names or IPs" hint="Comma separated. localhost and 127.0.0.1 are always included.">
              <input className="input" value={hosts} onChange={(e) => setHosts(e.target.value)} placeholder="registry.example.com, 10.0.0.5" />
            </Field>
            <button className="btn" disabled={act.busy} onClick={() => apply(() => api.setTLS(reg.name, { generate: true, hosts: hosts.split(",").map((h) => h.trim()).filter(Boolean) }), "HTTPS enabled")}>
              {act.busy ? "Applying…" : "Generate and enable"}
            </button>
          </section>
          <section className="card" aria-labelledby="up">
            <h2 id="up">Use your own certificate</h2>
            <Field label="Certificate chain (PEM)"><textarea className="input" value={cert} onChange={(e) => setCert(e.target.value)} placeholder="-----BEGIN CERTIFICATE-----" spellCheck={false} /></Field>
            <Field label="Private key (PEM)" hint="Applying restarts the registry briefly."><textarea className="input" value={key} onChange={(e) => setKey(e.target.value)} placeholder="-----BEGIN PRIVATE KEY-----" spellCheck={false} autoComplete="off" /></Field>
            <button className="btn" disabled={act.busy || !cert || !key} onClick={() => apply(async () => { await api.setTLS(reg.name, { cert, key }); setCert(""); setKey(""); }, "Certificate installed")}>Install certificate</button>
          </section>
        </>
      )}
    </>
  );
}
