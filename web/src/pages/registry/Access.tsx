import { api } from "../../api";
import { useLoad } from "../../hooks";
import { href } from "../../router";
import { Alert, Empty, RoleBadge, Skeleton } from "../../components/ui";
import type { TabProps } from "../RegistryDetail";

/** Which manager accounts can see and manage this registry (admins only). */
export function Access({ reg }: TabProps) {
  const accounts = useLoad(api.accounts, []);
  const rows = (accounts.data ?? []).filter((a) => !a.disabled && (a.role === "admin" || a.allRegistries || a.registries.includes(reg.name)));
  const why = (a: (typeof rows)[number]) => (a.role === "admin" ? "Administrator" : a.allRegistries ? "All registries" : "Assigned");
  return (
    <section className="card flush" aria-labelledby="acc">
      <div className="card-head"><h2 id="acc">Who has access</h2><span className="spacer" /><a href={href("accounts")}>Manage accounts</a></div>
      <Alert>{accounts.error}</Alert>
      {accounts.loading && !accounts.data ? <Skeleton rows={3} /> : rows.length === 0 ? <Empty title="Only you">No other account can see this registry.</Empty> : (
        <ul className="plain" style={{ padding: "4px 18px" }}>
          {rows.map((a) => (
            <li key={a.id}><strong>{a.username}</strong><span className="muted">{a.displayName !== a.username ? a.displayName : ""}</span><span className="spacer" /><span className="muted">{why(a)}</span><RoleBadge role={a.role} /></li>
          ))}
        </ul>
      )}
    </section>
  );
}
