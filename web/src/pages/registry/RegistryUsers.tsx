import { useState } from "react";
import { api } from "../../api";
import { useAction, useLoad } from "../../hooks";
import { useSession } from "../../session";
import { useConfirm, Dialog } from "../../components/dialog";
import { useToast } from "../../components/toast";
import { Alert, Empty, Field, Skeleton } from "../../components/ui";
import type { TabProps } from "../RegistryDetail";

export function RegistryUsers({ reg }: TabProps) {
  const s = useSession();
  const confirm = useConfirm();
  const toast = useToast();
  const users = useLoad(() => api.users(reg.name), [reg.name]);
  const act = useAction();
  const [editing, setEditing] = useState<string | null | undefined>(); // undefined closed, null = new

  const remove = async (u: string) => {
    const ok = await confirm({ title: `Remove ${u}?`, danger: true, confirmLabel: "Remove user",
      body: <p>They lose access to this registry immediately. The registry restarts briefly.</p> });
    if (ok && await act.run(() => api.removeUser(reg.name, u))) { toast.success(`Removed ${u}`); users.reload(); }
  };

  return (
    <>
      <section className="card flush" aria-labelledby="ru">
        <div className="card-head">
          <h2 id="ru">Registry users</h2><span className="spacer" />
          {s.canOperate && <button className="btn" onClick={() => setEditing(null)}>Add user</button>}
        </div>
        <Alert>{users.error ?? act.error}</Alert>
        {users.loading && !users.data ? <Skeleton rows={2} /> : users.data?.users.length === 0 ? (
          <Empty title="No users">Nobody can push or pull until a user is added.</Empty>
        ) : (
          <ul className="plain" style={{ padding: "4px 18px" }} aria-label="Registry users">
            {users.data?.users.map((u) => (
              <li key={u}>
                <span className="mono" style={{ flex: 1 }}>{u}</span>
                {s.canOperate && <>
                  <button className="btn secondary sm" onClick={() => setEditing(u)} aria-label={`Change password of ${u}`}>Change password</button>
                  <button className="btn danger sm" disabled={act.busy} onClick={() => remove(u)} aria-label={`Remove ${u}`}>Remove</button>
                </>}
              </li>
            ))}
          </ul>
        )}
      </section>
      <p className="muted">These credentials are used with <code>podman login</code> against the registry itself. They are separate from manager accounts.</p>
      {editing !== undefined && <UserDialog reg={reg.name} existing={editing} onClose={() => setEditing(undefined)}
        onDone={(u) => { setEditing(undefined); toast.success(`Saved ${u}`); users.reload(); }} />}
    </>
  );
}

function UserDialog({ reg, existing, onClose, onDone }: { reg: string; existing: string | null; onClose: () => void; onDone: (u: string) => void }) {
  const [user, setUser] = useState(existing ?? "");
  const [pass, setPass] = useState("");
  const act = useAction();
  const submit = async (e: React.FormEvent) => { e.preventDefault(); if (await act.run(() => api.setUser(reg, user, pass))) onDone(user); };
  return (
    <Dialog title={existing ? `Change password for ${existing}` : "Add registry user"} onClose={onClose} dismissible={!act.busy} footer={
      <><button className="btn secondary" onClick={onClose} disabled={act.busy}>Cancel</button><button className="btn" form="ru-form" disabled={act.busy}>{act.busy ? "Applying…" : "Save"}</button></>
    }>
      <form id="ru-form" onSubmit={submit}>
        {!existing && <Field label="Username"><input className="input" data-autofocus value={user} onChange={(e) => setUser(e.target.value)} required autoComplete="off" /></Field>}
        <Field label="Password" hint="8–72 characters. Saving restarts the registry briefly.">
          <input className="input" data-autofocus={!!existing} type="password" value={pass} onChange={(e) => setPass(e.target.value)} required autoComplete="new-password" />
        </Field>
        <Alert>{act.error}</Alert>
      </form>
    </Dialog>
  );
}
