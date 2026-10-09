import { useEffect, useState } from "react";
import { api, type AuditEntry, type AuditQuery } from "../api";
import { useTitle } from "../hooks";
import { Alert, Badge, Empty, Field, PageHead, Skeleton } from "../components/ui";

const ACTIONS = [
  "auth.login", "auth.logout", "auth.password.change", "registry.create", "registry.delete", "registry.start", "registry.stop",
  "registry.tag.delete", "registry.gc", "registry.user.set", "registry.user.remove", "registry.tls.set", "registry.tls.remove",
  "registry.config.update", "registry.scan.run", "registry.sign", "registry.signingkey.create", "registry.signingkey.delete", "registry.trustkey.add", "registry.trustkey.remove", "security.content.add", "security.content.delete", "account.create", "account.update", "account.delete", "account.password.reset",
];

const toISO = (local: string) => (local ? new Date(local).toISOString() : undefined);

export function Audit() {
  useTitle("Audit log");
  const [form, setForm] = useState({ actor: "", action: "", target: "", outcome: "", since: "", until: "" });
  const [applied, setApplied] = useState<AuditQuery>({});
  const [rows, setRows] = useState<AuditEntry[]>([]);
  const [pageSize, setPageSize] = useState(25);
  const [cursors, setCursors] = useState<number[]>([0]); // "before" id of each visited page; last = current
  const [more, setMore] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string>();
  const page = cursors.length;
  const before = cursors[cursors.length - 1];

  // Ask for one extra row to know whether a next page exists.
  useEffect(() => {
    let live = true;
    setLoading(true); setError(undefined);
    api.audit({ ...applied, before: before || undefined, limit: pageSize + 1 })
      .then((res) => { if (live) { setMore(res.entries.length > pageSize); setRows(res.entries.slice(0, pageSize)); } })
      .catch((e) => { if (live) setError((e as Error).message); })
      .finally(() => { if (live) setLoading(false); });
    return () => { live = false; };
  }, [applied, before, pageSize]);

  const apply = (e: React.FormEvent) => {
    e.preventDefault();
    setCursors([0]); setApplied({ actor: form.actor.trim(), action: form.action.trim(), target: form.target.trim(), outcome: form.outcome, since: toISO(form.since), until: toISO(form.until) });
  };
  const reset = () => { setForm({ actor: "", action: "", target: "", outcome: "", since: "", until: "" }); setCursors([0]); setApplied({}); };
  const set = (k: keyof typeof form) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => setForm({ ...form, [k]: e.target.value });

  return (
    <>
      <PageHead title="Audit log" subtitle="Who did what, and when. Passwords and secrets are never recorded."
        actions={<a className="btn secondary" href={api.auditCsvUrl(applied)} download>Export CSV</a>} />
      <form className="card" onSubmit={apply} aria-label="Filter audit log">
        <div className="grid" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(170px, 1fr))", gap: "0 14px" }}>
          <Field label="Actor"><input className="input" value={form.actor} onChange={set("actor")} placeholder="username" /></Field>
          <Field label="Action">
            <input className="input" list="actions" value={form.action} onChange={set("action")} placeholder="e.g. registry." />
            <datalist id="actions">{ACTIONS.map((a) => <option key={a} value={a} />)}</datalist>
          </Field>
          <Field label="Target"><input className="input" value={form.target} onChange={set("target")} placeholder="registry or user" /></Field>
          <Field label="Outcome">
            <select className="input" value={form.outcome} onChange={set("outcome")}><option value="">Any</option><option value="ok">ok</option><option value="denied">denied</option><option value="error">error</option></select>
          </Field>
          <Field label="From"><input className="input" type="datetime-local" value={form.since} onChange={set("since")} /></Field>
          <Field label="Until"><input className="input" type="datetime-local" value={form.until} onChange={set("until")} /></Field>
        </div>
        <div className="row"><button className="btn">Apply filters</button><button type="button" className="btn ghost" onClick={reset}>Reset</button></div>
      </form>

      <Alert>{error}</Alert>
      <div className="card flush">
        {loading && rows.length === 0 && page === 1 ? <Skeleton rows={5} /> : rows.length === 0 ? <Empty title="No matching events">Change the filters, or perform an action to create entries.</Empty> : (
          <>
            <div className="table-wrap" tabIndex={0} role="region" aria-label="Audit events, newest first">
              <table className="table audit-table" role="table">
                <caption className="sr-only">Audit events, newest first</caption>
                <thead><tr role="row"><th scope="col">Time</th><th scope="col">Actor</th><th scope="col">Action</th><th scope="col">Target</th><th scope="col">Outcome</th><th scope="col" >Details</th><th scope="col">IP</th></tr></thead>
                <tbody>
                  {rows.map((e) => (
                    <tr key={e.id} role="row">
                      <td role="cell" data-label="Time" className="num" style={{ whiteSpace: "nowrap" }}><time dateTime={e.time}>{new Date(e.time).toLocaleString()}</time></td>
                      <td role="cell" data-label="Actor" style={{ whiteSpace: "nowrap" }}><strong>{e.actor || "—"}</strong>{e.actorRole && <span className="muted"> · {e.actorRole}</span>}</td>
                      <td role="cell" data-label="Action"><code>{e.action}</code></td>
                      <td role="cell" data-label="Target">{e.target || <span className="muted">—</span>}</td>
                      <td role="cell" data-label="Outcome"><Badge tone={e.outcome === "ok" ? "ok" : e.outcome === "denied" ? "warn" : "bad"}>{e.outcome}</Badge></td>
                      <td role="cell" data-label="Details"><span className="detail-chips">{Object.entries(e.detail ?? {}).map(([k, v]) => <span key={k} className="chip">{k}={v}</span>)}</span></td>
                      <td role="cell" data-label="IP" className="mono muted nw">{e.ip}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="pager">
              <span className="num">Page {page} · {rows.length} event{rows.length === 1 ? "" : "s"}</span>
              <span className="spacer" />
              <label className="row" style={{ gap: 6 }}>Rows per page
                <select className="input" style={{ width: "auto" }} value={pageSize} onChange={(e) => { setPageSize(Number(e.target.value)); setCursors([0]); }}>
                  {[10, 25, 50, 100].map((n) => <option key={n} value={n}>{n}</option>)}
                </select>
              </label>
              <button className="btn secondary sm" disabled={loading || page === 1} onClick={() => setCursors((c) => c.slice(0, -1))}>Previous</button>
              <button className="btn secondary sm" disabled={loading || !more} onClick={() => setCursors((c) => [...c, rows[rows.length - 1].id])}>Next</button>
            </div>
          </>
        )}
      </div>
    </>
  );
}
