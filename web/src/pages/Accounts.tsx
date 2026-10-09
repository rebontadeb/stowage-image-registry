import { useState } from "react";
import { api, type Account, type Role } from "../api";
import { fmtDate, useAction, useLoad, useTitle } from "../hooks";
import { useSession } from "../session";
import { useConfirm, Dialog } from "../components/dialog";
import { useToast } from "../components/toast";
import { DataTable, type Column } from "../components/DataTable";
import { Alert, Badge, Empty, Field, PageHead, RoleBadge } from "../components/ui";

const ROLE_HELP: Record<Role, string> = {
  admin: "Full control, including accounts and the audit log. Sees every registry.",
  operator: "Manages the registries in scope: start/stop, images, users, TLS, configuration.",
  viewer: "Read-only access to the registries in scope.",
};

export function Accounts() {
  const s = useSession();
  const confirm = useConfirm();
  const toast = useToast();
  useTitle("Accounts & access");
  const accounts = useLoad(api.accounts, []);
  const fleet = useLoad(api.fleet, []);
  const act = useAction();
  const [dialog, setDialog] = useState<{ kind: "create" } | { kind: "edit" | "reset"; a: Account }>();
  const regNames = (fleet.data?.registries ?? []).map((r) => r.name);

  const scope = (a: Account) => a.role === "admin" || a.allRegistries ? "All registries" : a.registries.length ? `${a.registries.length} registr${a.registries.length === 1 ? "y" : "ies"}` : "None";

  const toggle = async (a: Account) => {
    const disabling = !a.disabled;
    if (disabling && !(await confirm({ title: `Disable ${a.username}?`, danger: true, confirmLabel: "Disable", body: <p>They are signed out immediately and cannot sign in until re-enabled.</p> }))) return;
    if (await act.run(() => api.updateAccount(a.id, { disabled: disabling }))) { toast.success(`${a.username} ${disabling ? "disabled" : "enabled"}`); accounts.reload(); }
  };
  const remove = async (a: Account) => {
    if (!(await confirm({ title: `Delete ${a.username}?`, danger: true, confirmLabel: "Delete account", requireText: a.username, body: <p>The account and its sessions are removed. Audit entries are kept.</p> }))) return;
    if (await act.run(() => api.deleteAccount(a.id))) { toast.success(`Deleted ${a.username}`); accounts.reload(); }
  };

  const columns: Column<Account>[] = [
    { key: "u", header: "Account", sort: (a) => a.username.toLowerCase(), render: (a) => <><strong>{a.username}</strong>{a.displayName && a.displayName !== a.username && <div className="muted">{a.displayName}</div>}{a.id === s.me!.id && <Badge tone="info">you</Badge>}</> },
    { key: "r", header: "Role", sort: (a) => a.role, render: (a) => <RoleBadge role={a.role} /> },
    { key: "s", header: "Sign-in", className: "hide-sm", render: (a) => a.source === "oidc" ? <Badge tone="info">SSO</Badge> : <span className="muted">Password</span> },
    { key: "a", header: "Access", className: "nw", render: (a) => scope(a) },
    { key: "l", header: "Last sign-in", className: "hide-sm", sort: (a) => a.lastLogin, render: (a) => <span className="muted">{fmtDate(a.lastLogin)}</span> },
    { key: "st", header: "Status", sort: (a) => Number(a.disabled), render: (a) => a.disabled ? <Badge tone="bad">Disabled</Badge> : a.mustChangePassword ? <Badge tone="warn">Must change password</Badge> : <Badge tone="ok">Active</Badge> },
    { key: "x", header: "", align: "right", render: (a) => (
      <span className="row end" style={{ flexWrap: "nowrap", justifyContent: "flex-end" }}>
        <button className="btn secondary sm" onClick={() => setDialog({ kind: "edit", a })} aria-label={`Edit ${a.username}`}>Edit</button>
        {a.source === "local" && <button className="btn secondary sm" onClick={() => setDialog({ kind: "reset", a })} aria-label={`Reset password of ${a.username}`}>Reset password</button>}
        {a.id !== s.me!.id && <button className="btn secondary sm" disabled={act.busy} onClick={() => toggle(a)} aria-label={`${a.disabled ? "Enable" : "Disable"} ${a.username}`}>{a.disabled ? "Enable" : "Disable"}</button>}
        {a.id !== s.me!.id && <button className="btn danger sm" disabled={act.busy} onClick={() => remove(a)} aria-label={`Delete ${a.username}`}>Delete</button>}
      </span>) },
  ];

  return (
    <>
      <PageHead title="Accounts & access" subtitle="Who can sign in to Stowage, what they may do, and which tenants' registries they can see."
        actions={<button className="btn" onClick={() => setDialog({ kind: "create" })}>New account</button>} />
      <Alert>{accounts.error ?? act.error}</Alert>
      <div className="card flush">
        <DataTable columns={columns} rows={accounts.data ?? []} rowKey={(a) => String(a.id)} caption="Manager accounts" loading={accounts.loading}
          initialSort={{ key: "u", dir: "asc" }} empty={<Empty title="No accounts" />} />
      </div>
      <p className="muted">Single sign-on users appear here after their first sign-in. Their role follows their identity-provider groups; assign registry access here.</p>

      {dialog?.kind === "create" && <CreateDialog regNames={regNames} onClose={() => setDialog(undefined)} onDone={(u) => { setDialog(undefined); toast.success(`Created ${u}`); accounts.reload(); }} />}
      {dialog?.kind === "edit" && <EditDialog a={dialog.a} regNames={regNames} self={dialog.a.id === s.me!.id} onClose={() => setDialog(undefined)} onDone={() => { setDialog(undefined); toast.success("Account updated"); accounts.reload(); }} />}
      {dialog?.kind === "reset" && <ResetDialog a={dialog.a} onClose={() => setDialog(undefined)} onDone={() => { setDialog(undefined); toast.success("Password reset; the user was signed out everywhere"); accounts.reload(); }} />}
    </>
  );
}

function Scope({ role, all, setAll, regs, setRegs, names }: { role: Role; all: boolean; setAll: (v: boolean) => void; regs: string[]; setRegs: (v: string[]) => void; names: string[] }) {
  if (role === "admin") return <p className="muted">Administrators can see every registry.</p>;
  return (
    <fieldset style={{ border: 0, padding: 0, margin: "0 0 14px" }}>
      <legend className="label" style={{ fontWeight: 600, marginBottom: 6 }}>Registry access</legend>
      <label className="check"><input type="radio" checked={all} onChange={() => setAll(true)} /> All registries, including future ones</label>
      <label className="check"><input type="radio" checked={!all} onChange={() => setAll(false)} /> Only selected registries</label>
      {!all && (
        <div className="check-list" role="group" aria-label="Registries">
          {names.length === 0 ? <span className="muted">No registries exist yet.</span> : names.map((n) => (
            <label key={n} className="check"><input type="checkbox" checked={regs.includes(n)} onChange={(e) => setRegs(e.target.checked ? [...regs, n] : regs.filter((x) => x !== n))} />{n}</label>
          ))}
        </div>
      )}
    </fieldset>
  );
}

function RoleSelect({ value, onChange, disabled }: { value: Role; onChange: (r: Role) => void; disabled?: boolean }) {
  return (
    <Field label="Role" hint={ROLE_HELP[value]}>
      <select className="input" value={value} disabled={disabled} onChange={(e) => onChange(e.target.value as Role)}>
        <option value="viewer">Viewer</option><option value="operator">Operator</option><option value="admin">Administrator</option>
      </select>
    </Field>
  );
}

function CreateDialog({ regNames, onClose, onDone }: { regNames: string[]; onClose: () => void; onDone: (u: string) => void }) {
  const [f, setF] = useState({ username: "", displayName: "", password: "", role: "viewer" as Role, all: false, regs: [] as string[], must: true });
  const act = useAction();
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (await act.run(() => api.createAccount({ username: f.username, displayName: f.displayName, password: f.password, role: f.role, allRegistries: f.all, registries: f.regs, mustChangePassword: f.must }))) onDone(f.username);
  };
  return (
    <Dialog wide title="New account" onClose={onClose} dismissible={!act.busy} footer={
      <><button className="btn secondary" onClick={onClose} disabled={act.busy}>Cancel</button><button className="btn" form="acc-new" disabled={act.busy}>{act.busy ? "Creating…" : "Create account"}</button></>
    }>
      <form id="acc-new" onSubmit={submit}>
        <Field label="Username" hint="Letters, digits, dot, dash, underscore or @."><input className="input" data-autofocus value={f.username} onChange={(e) => setF({ ...f, username: e.target.value })} required autoComplete="off" /></Field>
        <Field label="Display name (optional)"><input className="input" value={f.displayName} onChange={(e) => setF({ ...f, displayName: e.target.value })} /></Field>
        <Field label="Initial password" hint="12–72 characters. Share it securely."><input className="input" type="password" value={f.password} onChange={(e) => setF({ ...f, password: e.target.value })} required autoComplete="new-password" /></Field>
        <label className="check" style={{ marginBottom: 14 }}><input type="checkbox" checked={f.must} onChange={(e) => setF({ ...f, must: e.target.checked })} /> Require a new password at first sign-in</label>
        <RoleSelect value={f.role} onChange={(role) => setF({ ...f, role })} />
        <Scope role={f.role} all={f.all} setAll={(all) => setF({ ...f, all })} regs={f.regs} setRegs={(regs) => setF({ ...f, regs })} names={regNames} />
        <Alert>{act.error}</Alert>
      </form>
    </Dialog>
  );
}

function EditDialog({ a, regNames, self, onClose, onDone }: { a: Account; regNames: string[]; self: boolean; onClose: () => void; onDone: () => void }) {
  const [f, setF] = useState({ displayName: a.displayName, role: a.role, all: a.allRegistries, regs: a.registries });
  const act = useAction();
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (await act.run(() => api.updateAccount(a.id, { displayName: f.displayName, role: f.role, allRegistries: f.all, registries: f.regs }))) onDone();
  };
  return (
    <Dialog wide title={`Edit ${a.username}`} onClose={onClose} dismissible={!act.busy} footer={
      <><button className="btn secondary" onClick={onClose} disabled={act.busy}>Cancel</button><button className="btn" form="acc-edit" disabled={act.busy}>{act.busy ? "Saving…" : "Save changes"}</button></>
    }>
      <form id="acc-edit" onSubmit={submit}>
        {a.source === "oidc" && <Alert kind="info">This account signs in with single sign-on. Its role is re-synced from the identity provider's groups at every sign-in.</Alert>}
        <Field label="Display name"><input className="input" data-autofocus value={f.displayName} onChange={(e) => setF({ ...f, displayName: e.target.value })} /></Field>
        <RoleSelect value={f.role} onChange={(role) => setF({ ...f, role })} disabled={self} />
        {self && <p className="muted">You cannot change your own role.</p>}
        <Scope role={f.role} all={f.all} setAll={(all) => setF({ ...f, all })} regs={f.regs} setRegs={(regs) => setF({ ...f, regs })} names={regNames} />
        <Alert>{act.error}</Alert>
      </form>
    </Dialog>
  );
}

function ResetDialog({ a, onClose, onDone }: { a: Account; onClose: () => void; onDone: () => void }) {
  const [pw, setPw] = useState("");
  const [must, setMust] = useState(true);
  const act = useAction();
  const submit = async (e: React.FormEvent) => { e.preventDefault(); if (await act.run(() => api.resetPassword(a.id, pw, must))) onDone(); };
  return (
    <Dialog title={`Reset password for ${a.username}`} onClose={onClose} dismissible={!act.busy} footer={
      <><button className="btn secondary" onClick={onClose} disabled={act.busy}>Cancel</button><button className="btn" form="acc-reset" disabled={act.busy}>{act.busy ? "Saving…" : "Reset password"}</button></>
    }>
      <form id="acc-reset" onSubmit={submit}>
        <Field label="New password" hint="12–72 characters. The user is signed out on every device."><input className="input" data-autofocus type="password" value={pw} onChange={(e) => setPw(e.target.value)} required autoComplete="new-password" /></Field>
        <label className="check"><input type="checkbox" checked={must} onChange={(e) => setMust(e.target.checked)} /> Require a new password at next sign-in</label>
        <Alert>{act.error}</Alert>
      </form>
    </Dialog>
  );
}
