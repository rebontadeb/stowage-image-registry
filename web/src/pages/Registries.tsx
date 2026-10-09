import { useMemo, useState } from "react";
import { api, type FleetItem } from "../api";
import { fmtBytes, fmtDate, useAction, useDebounced, useLoad, useTitle } from "../hooks";
import { useSession } from "../session";
import { go, href } from "../router";
import { useToast } from "../components/toast";
import { Dialog } from "../components/dialog";
import { DataTable, type Column } from "../components/DataTable";
import { Alert, Badge, Empty, Field, PageHead, StatusBadge } from "../components/ui";
import { VulnCounts } from "../components/security";

export function Registries() {
  const s = useSession();
  const toast = useToast();
  useTitle("Registries");
  const fleet = useLoad(api.fleet, [], 10000);
  const act = useAction();
  const [q, setQ] = useState("");
  const [status, setStatus] = useState("");
  const [tls, setTls] = useState("");
  const [creating, setCreating] = useState(false);
  const dq = useDebounced(q.trim().toLowerCase());

  const rows = useMemo(() => (fleet.data?.registries ?? []).filter((r) =>
    (!dq || r.name.includes(dq) || r.customer.toLowerCase().includes(dq)) &&
    (!status || r.state === status) &&
    (!tls || (tls === "yes") === r.tls)), [fleet.data, dq, status, tls]);

  const toggle = async (r: FleetItem) => {
    const stopping = r.state !== "stopped";
    if (await act.run(() => (stopping ? api.stop(r.name) : api.start(r.name)))) {
      toast.success(`${r.name} ${stopping ? "stopped" : "started"}`);
      fleet.reload();
    }
  };

  const columns: Column<FleetItem>[] = [
    { key: "name", header: "Name", sort: (r) => r.name, render: (r) => <a href={href("registries", r.name)}><strong>{r.name}</strong></a> },
    { key: "customer", header: "Tenant", sort: (r) => r.customer.toLowerCase(), render: (r) => r.customer },
    { key: "state", header: "Status", sort: (r) => r.state, render: (r) => <StatusBadge state={r.state} /> },
    { key: "tls", header: "TLS", sort: (r) => Number(r.tls), render: (r) => r.tls ? <Badge tone="ok">HTTPS</Badge> : <Badge tone="warn">HTTP</Badge> },
    ...(s.config?.security ? [{
      key: "vuln", header: "Vulnerabilities", sort: (r: FleetItem) => (r.scannedImages ? r.criticalVulns * 1000 + r.highVulns : null),
      render: (r: FleetItem) => r.scannedImages ? <VulnCounts s={{ critical: r.criticalVulns, high: r.highVulns, medium: 0, low: 0 }} levels={["critical", "high"]} /> : <span className="muted">Not scanned</span>,
    }] : []),
    { key: "used", header: "Storage", align: "right", sort: (r) => r.usedBytes, render: (r) => <span className="num">{fmtBytes(r.usedBytes)}</span> },
    { key: "host", header: "Address", className: "hide-sm", render: (r) => <span className="mono">{r.host || "—"}</span> },
    { key: "created", header: "Created", className: "hide-sm", sort: (r) => r.createdAt, render: (r) => <span className="muted">{fmtDate(r.createdAt)}</span> },
    ...(s.canOperate ? [{
      key: "act", header: "", align: "right" as const,
      render: (r: FleetItem) => <button className="btn secondary sm" disabled={act.busy || r.state === "missing"} onClick={() => toggle(r)}
        aria-label={`${r.state === "stopped" ? "Start" : "Stop"} ${r.name}`}>{r.state === "stopped" ? "Start" : "Stop"}</button>,
    }] : []),
  ];

  const filtered = !!(dq || status || tls);
  return (
    <>
      <PageHead title="Registries" subtitle="Each tenant has an isolated registry with its own users and storage."
        actions={s.isAdmin && <button className="btn" onClick={() => setCreating(true)}>New registry</button>} />
      <Alert>{fleet.error ?? act.error}</Alert>
      <div className="card flush">
        <div className="card-head" role="search">
          <div className="search"><label className="sr-only" htmlFor="rq">Search registries</label>
            <input id="rq" className="input" type="search" placeholder="Search name or tenant" value={q} onChange={(e) => setQ(e.target.value)} /></div>
          <label className="sr-only" htmlFor="rs">Status</label>
          <select id="rs" className="input" style={{ width: "auto" }} value={status} onChange={(e) => setStatus(e.target.value)}>
            <option value="">Any status</option><option value="running">Running</option><option value="starting">Starting</option><option value="stopped">Stopped</option><option value="missing">Missing</option>
          </select>
          <label className="sr-only" htmlFor="rt">TLS</label>
          <select id="rt" className="input" style={{ width: "auto" }} value={tls} onChange={(e) => setTls(e.target.value)}>
            <option value="">Any transport</option><option value="yes">HTTPS</option><option value="no">HTTP only</option>
          </select>
          {filtered && <button className="btn ghost sm" onClick={() => { setQ(""); setStatus(""); setTls(""); }}>Clear filters</button>}
        </div>
        <DataTable columns={columns} rows={rows} rowKey={(r) => r.name} caption="Registries" loading={fleet.loading}
          initialSort={{ key: "name", dir: "asc" }} resetKey={`${dq}|${status}|${tls}`}
          onRowOpen={(r) => go("registries", r.name)}
          empty={filtered
            ? <Empty title="No registries match">Try different search terms or clear the filters.</Empty>
            : <Empty title="No registries yet" action={s.isAdmin ? <button className="btn" onClick={() => setCreating(true)}>Create the first registry</button> : undefined}>
                {s.isAdmin ? "Create one to give a tenant a private image registry." : "Nothing has been shared with you yet. Ask an administrator for access."}
              </Empty>} />
      </div>
      {creating && <CreateDialog onClose={() => setCreating(false)} onCreated={(n) => { setCreating(false); toast.success(`Registry ${n} created`); go("registries", n); }} />}
    </>
  );
}

function CreateDialog({ onClose, onCreated }: { onClose: () => void; onCreated: (name: string) => void }) {
  const [name, setName] = useState("");
  const [tenant, setTenant] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const act = useAction();
  const nameOk = name === "" || /^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$/.test(name);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    const body = { name, customer: tenant, ...(username || password ? { username, password } : {}) };
    if (await act.run(() => api.create(body))) onCreated(name);
  };

  return (
    <Dialog title="New registry" onClose={onClose} dismissible={!act.busy} footer={
      <>
        <button type="button" className="btn secondary" onClick={onClose} disabled={act.busy}>Cancel</button>
        <button className="btn" form="create-reg" disabled={act.busy || !nameOk}>{act.busy ? "Creating…" : "Create registry"}</button>
      </>
    }>
      <form id="create-reg" onSubmit={submit}>
        <Field label="Name" hint="Lowercase letters, digits and dashes, up to 32 characters." error={nameOk ? undefined : "Use lowercase letters, digits and dashes; start and end with a letter or digit."}>
          <input className="input" data-autofocus value={name} onChange={(e) => setName(e.target.value.toLowerCase())} required aria-invalid={!nameOk} maxLength={32} />
        </Field>
        <Field label="Tenant" hint="The organisation or team this registry belongs to."><input className="input" value={tenant} onChange={(e) => setTenant(e.target.value)} required /></Field>
        <Field label="First registry user (optional)" hint="Without a user nobody can push or pull. You can add users later.">
          <input className="input" value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="off" placeholder="username" />
        </Field>
        <Field label="Password" hint="8–72 characters.">
          <input className="input" type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" required={!!username} />
        </Field>
        <Alert>{act.error}</Alert>
      </form>
    </Dialog>
  );
}
