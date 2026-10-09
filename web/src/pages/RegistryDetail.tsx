import { api, type Reg } from "../api";
import { useAction, useLoad, useTitle } from "../hooks";
import { useSession } from "../session";
import { href } from "../router";
import { useToast } from "../components/toast";
import { Alert, PageHead, Skeleton, StatusBadge } from "../components/ui";
import { Overview } from "./registry/Overview";
import { Images } from "./registry/Images";
import { RegistryUsers } from "./registry/RegistryUsers";
import { Tls } from "./registry/Tls";
import { Config } from "./registry/Config";
import { Delete } from "./registry/Delete";
import { Access } from "./registry/Access";
import { Security } from "./registry/Security";

export interface TabProps { reg: Reg; reload: () => void }

export function RegistryDetail({ name, tab, sub }: { name: string; tab?: string; sub?: string }) {
  const s = useSession();
  const toast = useToast();
  const { data: reg, error, reload } = useLoad(() => api.get(name), [name], 5000);
  const act = useAction();
  useTitle(name);

  const tabs = [
    { id: "overview", label: "Overview" },
    { id: "images", label: "Images" },
    { id: "users", label: "Registry users" },
    { id: "tls", label: "TLS" },
    ...(s.config?.security ? [{ id: "security", label: "Security" }] : []),
    ...(s.canOperate ? [{ id: "config", label: "Configuration" }] : []),
    ...(s.isAdmin ? [{ id: "access", label: "Access" }] : []),
    ...(s.isAdmin ? [{ id: "delete", label: "Delete registry" }] : []),
  ];
  const current = tabs.find((t) => t.id === tab)?.id ?? "overview";

  if (!reg) {
    return (
      <>
        <PageHead crumbs={<a href={href("registries")}>Registries</a>} title={name} />
        {error ? <Alert>{error}</Alert> : <div className="card"><Skeleton /></div>}
      </>
    );
  }

  const stopped = reg.state === "stopped";
  const toggle = async () => {
    if (await act.run(() => (stopped ? api.start(reg.name) : api.stop(reg.name)))) {
      toast.success(`${reg.name} ${stopped ? "started" : "stopped"}`);
      reload();
    }
  };
  const props: TabProps = { reg, reload };

  return (
    <>
      <PageHead
        crumbs={<><a href={href("registries")}>Registries</a> / {reg.name}</>}
        title={<span className="row" style={{ gap: 12 }}>{reg.name} <StatusBadge state={reg.state} /></span>}
        subtitle={reg.customer}
        actions={s.canOperate && <button className="btn secondary" disabled={act.busy || reg.state === "missing"} onClick={toggle}>{stopped ? "Start" : "Stop"}</button>} />
      <Alert>{act.error ?? (error ? `Connection problem: ${error}` : undefined)}</Alert>
      <nav className="tabs" aria-label="Registry sections">
        {tabs.map((t) => (
          <a key={t.id} href={href("registries", reg.name, t.id)} aria-current={current === t.id ? "page" : undefined}>{t.label}</a>
        ))}
      </nav>
      {current === "overview" && <Overview {...props} />}
      {current === "images" && <Images {...props} repo={sub} />}
      {current === "users" && <RegistryUsers {...props} />}
      {current === "tls" && <Tls {...props} />}
      {current === "security" && s.config?.security && <Security {...props} />}
      {current === "config" && s.canOperate && <Config {...props} />}
      {current === "access" && s.isAdmin && <Access {...props} />}
      {current === "delete" && s.isAdmin && <Delete {...props} />}
    </>
  );
}
