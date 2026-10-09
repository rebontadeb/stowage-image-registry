import { api } from "../../api";
import { useAction } from "../../hooks";
import { go } from "../../router";
import { useConfirm } from "../../components/dialog";
import { useToast } from "../../components/toast";
import { Alert } from "../../components/ui";
import type { TabProps } from "../RegistryDetail";

export function Delete({ reg }: TabProps) {
  const confirm = useConfirm();
  const toast = useToast();
  const del = useAction();

  const remove = async () => {
    let keep = false;
    const ok = await confirm({
      title: `Delete registry ${reg.name}?`, danger: true, confirmLabel: "Delete registry", requireText: reg.name,
      body: (
        <>
          <p>This removes the registry, its users and its settings. <strong>All stored images are deleted</strong> unless you keep the data volume.</p>
          <label className="check"><input type="checkbox" onChange={(e) => (keep = e.target.checked)} /> Keep the data volume</label>
        </>
      ),
    });
    if (ok && await del.run(() => api.remove(reg.name, keep))) { toast.success(`Registry ${reg.name} deleted`); go("registries"); }
  };

  return (
    <section className="card" aria-labelledby="dz" style={{ borderColor: "var(--danger)" }}>
      <h2 id="dz">Delete registry</h2>
      <p className="muted">Permanently removes this tenant's registry, its users and its settings. This cannot be undone.</p>
      <Alert>{del.error}</Alert>
      <button className="btn danger" onClick={remove} disabled={del.busy}>Delete registry…</button>
    </section>
  );
}
