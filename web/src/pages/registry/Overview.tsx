import { api } from "../../api";
import { fmtBytes, fmtDate, useLoad } from "../../hooks";
import { useSession } from "../../session";
import { Alert, Badge, Code } from "../../components/ui";
import type { TabProps } from "../RegistryDetail";

export function Overview({ reg }: TabProps) {
  const usage = useLoad(() => api.usage(reg.name), [reg.name, reg.state]);
  const s = useSession();
  const secOn = !!s.config?.security;
  const running = reg.state === "running";
  const repos = useLoad(() => (running ? api.repoSummaries(reg.name) : Promise.resolve(undefined)), [reg.name, reg.state]);
  const scans = useLoad(() => (secOn ? api.scans(reg.name, "") : Promise.resolve([])), [reg.name, secOn]);
  const signing = useLoad(() => (secOn ? api.signing(reg.name) : Promise.resolve(undefined)), [reg.name, secOn]);
  const host = reg.host || `127.0.0.1:${reg.hostPort}`;
  const flag = reg.tls ? "" : " --tls-verify=false";

  const done = (kind: string) => (scans.data ?? []).filter((x) => x.kind === kind && x.status === "done");
  const vt = { critical: 0, high: 0, medium: 0, low: 0, fixable: 0 };
  for (const x of done("vuln")) {
    const m = x.summary as Partial<typeof vt>;
    vt.critical += m.critical ?? 0; vt.high += m.high ?? 0; vt.medium += m.medium ?? 0; vt.low += m.low ?? 0; vt.fixable += m.fixable ?? 0;
  }
  const sigs = { signed: 0, unsigned: 0, invalid: 0, unverified: 0 };
  for (const x of done("sig")) { const k = (x.summary as { status: keyof typeof sigs }).status; if (k in sigs) sigs[k]++; }
  const scanned = done("vuln").length;
  const pending = (scans.data ?? []).filter((x) => x.status === "queued" || x.status === "running").length;
  const none = <span className="muted">—</span>;

  return (
    <>
      <div className="grid two even">
        <section className="card" aria-labelledby="st">
          <h2 id="st">Status</h2>
          <dl className="kv">
            <dt>Address</dt><dd className="mono">{reg.url || "—"}</dd>
            <dt>Transport</dt><dd>{reg.tls ? "HTTPS" : "Plain HTTP"}</dd>
            <dt>Storage used</dt><dd className="num">{usage.data ? fmtBytes(usage.data.usedBytes) : usage.error ? <span className="muted">not available on this runtime</span> : "—"}</dd>
            <dt>Storage size</dt><dd>{reg.storageSize}</dd>
            <dt>Image</dt><dd className="mono">{reg.image}</dd>
            <dt>Created</dt><dd>{fmtDate(reg.createdAt)}</dd>
          </dl>
        </section>
        <section className="card" aria-labelledby="ct">
          <h2 id="ct">Contents</h2>
          {!running ? <p className="muted">Start the registry to see its contents.</p> : repos.error ? <p className="muted">Contents unavailable: {repos.error}</p> : (
            <dl className="kv">
              <dt>Repositories</dt><dd className="num">{repos.data ? repos.data.length : "—"}</dd>
              <dt>Image tags</dt><dd className="num">{repos.data ? repos.data.reduce((n, r) => n + r.tags, 0) : "—"}</dd>
              {secOn && <>
                <dt>Scanned images</dt><dd className="num">{scans.data ? scanned : "—"}{pending > 0 && <span className="muted"> · {pending} in progress</span>}</dd>
                <dt>Vulnerabilities</dt>
                <dd>{scanned === 0 ? none : (
                  <span className="detail-chips">
                    <Badge tone={vt.critical ? "bad" : "ok"}>{vt.critical} critical</Badge>
                    <Badge tone={vt.high ? "warn" : "ok"}>{vt.high} high</Badge>
                    <Badge>{vt.medium} medium</Badge><Badge>{vt.low} low</Badge>
                  </span>)}</dd>
                <dt>Fixable</dt><dd className="num">{scanned === 0 ? none : vt.fixable}</dd>
                <dt>Signatures</dt>
                <dd>{done("sig").length === 0 ? none : (
                  <span className="detail-chips">
                    <Badge tone="ok">{sigs.signed} signed</Badge>
                    <Badge tone={sigs.unsigned ? "warn" : "ok"}>{sigs.unsigned} unsigned</Badge>
                    {sigs.invalid > 0 && <Badge tone="bad">{sigs.invalid} invalid</Badge>}
                  </span>)}</dd>
                <dt>Signing key</dt><dd>{signing.data ? (signing.data.signingKey ? <span className="mono" title={signing.data.signingKey.fingerprint}>{signing.data.signingKey.fingerprint.slice(0, 16)}…</span> : <span className="muted">none</span>) : none}</dd>
                <dt>Trusted keys</dt><dd className="num">{signing.data ? signing.data.trustedKeys.length : "—"}</dd>
              </>}
            </dl>
          )}
        </section>
      </div>
      <section className="card" aria-labelledby="cn">
          <h2 id="cn">Connect</h2>
          <p className="muted">Sign in with a registry user (Registry users tab), then tag and push.</p>
          <Code>{`podman login${flag} ${host}`}</Code>
          <Code>{`podman tag myapp:latest ${host}/myteam/myapp:latest\npodman push${flag} ${host}/myteam/myapp:latest`}</Code>
          {reg.tls && <p className="muted">A self-signed certificate needs <code>--tls-verify=false</code> or to be trusted on the client.</p>}
        </section>
      {!reg.tls && <Alert kind="warn">This registry uses plain HTTP: passwords and images travel unencrypted. Enable HTTPS in the TLS tab.</Alert>}
    </>
  );
}
