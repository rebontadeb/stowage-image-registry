import { api, type FleetItem } from "../api";
import { fmtBytes, timeAgo, useLoad, useTitle } from "../hooks";
import { useSession } from "../session";
import { href } from "../router";
import { Alert, Badge, Empty, Kpi, PageHead, Skeleton, StatusBadge } from "../components/ui";

function attention(r: FleetItem): string[] {
  const out: string[] = [];
  if (r.state === "missing") out.push("Workload is missing");
  else if (r.state === "stopped") out.push("Stopped");
  else if (r.state === "starting") out.push("Starting");
  else if (!r.tls) out.push("Running without TLS");
  if (r.criticalVulns > 0) out.push(`${r.criticalVulns} critical ${r.criticalVulns === 1 ? "vulnerability" : "vulnerabilities"}`);
  return out;
}

export function Dashboard() {
  const s = useSession();
  useTitle("Dashboard");
  const fleet = useLoad(api.fleet, [], 15000);
  const audit = useLoad(() => (s.isAdmin ? api.audit({ limit: 8 }) : Promise.resolve(null)), [s.isAdmin], 30000);
  const sum = fleet.data?.summary;
  const needs = (fleet.data?.registries ?? []).map((r) => ({ r, why: attention(r) })).filter((x) => x.why.length > 0);
  const unhealthy = (sum?.stopped ?? 0) + (sum?.missing ?? 0) + (sum?.starting ?? 0);

  return (
    <>
      <PageHead title="Dashboard" subtitle={s.isAdmin ? "Fleet health across all tenants' registries." : "Health of the registries you have access to."} />
      <Alert>{fleet.error}</Alert>
      <div className="grid kpis">
        <Kpi label="Registries" value={sum?.total ?? "—"} sub={s.isAdmin ? "all tenants" : "in your scope"} />
        <Kpi label="Running" value={sum ? `${sum.running}` : "—"} sub={sum ? `of ${sum.total}` : undefined} tone={sum && sum.total > 0 && sum.running === sum.total ? "good" : undefined} />
        <Kpi label="Need attention" value={sum ? unhealthy : "—"} sub="stopped, starting or missing" tone={unhealthy > 0 ? "warn" : "good"} />
        <Kpi label="Without TLS" value={sum?.noTLS ?? "—"} sub={sum ? `${sum.tls} use HTTPS` : undefined} tone={sum && sum.noTLS > 0 ? "warn" : "good"} />
        {s.config?.security && (
          <Kpi label="Critical vulnerabilities" value={sum ? sum.criticalVulns : "—"} tone={sum && sum.scannedImages > 0 ? (sum.criticalVulns > 0 ? "bad" : "good") : undefined}
            sub={sum ? (sum.scannedImages === 0 ? "no images scanned yet" : `${sum.highVulns} high · ${sum.scannedImages} image${sum.scannedImages === 1 ? "" : "s"} scanned`) : undefined} />
        )}
        <Kpi label="Storage used" value={sum ? fmtBytes(sum.usedBytes) : "—"} sub="measured every minute" />
      </div>

      <div className={`grid ${s.isAdmin ? "two" : ""}`}>
        <section className="card flush" aria-labelledby="att">
          <div className="card-head"><h2 id="att">Needs attention</h2><span className="spacer" />{needs.length > 0 && <Badge tone="warn">{needs.length}</Badge>}</div>
          {fleet.loading && !fleet.data ? <Skeleton /> : needs.length === 0 ? (
            <Empty title="All clear">Every registry is running with TLS enabled.</Empty>
          ) : (
            <ul className="plain" style={{ padding: "4px 18px" }}>
              {needs.slice(0, 8).map(({ r, why }) => (
                <li key={r.name}>
                  <a href={href("registries", r.name)}><strong>{r.name}</strong></a>
                  <span className="muted">{r.customer}</span>
                  <span className="spacer" />
                  <StatusBadge state={r.state} />
                  {why.map((w) => <Badge key={w} tone={w.includes("critical") ? "bad" : "warn"}>{w}</Badge>)}
                </li>
              ))}
            </ul>
          )}
          {needs.length > 8 && <div className="pager"><a href={href("registries")}>View all {needs.length}</a></div>}
        </section>

        {s.isAdmin && (
          <section className="card flush" aria-labelledby="act">
            <div className="card-head"><h2 id="act">Recent activity</h2><span className="spacer" /><a href={href("audit")}>Audit log</a></div>
            {audit.loading && !audit.data ? <Skeleton /> : !audit.data?.entries.length ? <Empty title="No activity yet" /> : (
              <ul className="plain" style={{ padding: "4px 18px" }}>
                {audit.data.entries.map((e) => (
                  <li key={e.id}>
                    <div style={{ minWidth: 0 }}>
                      <div><strong>{e.actor || "—"}</strong> <code>{e.action}</code>{e.target && <> on <strong>{e.target}</strong></>}</div>
                      <div className="muted" style={{ fontSize: 12 }}>{timeAgo(e.time)}</div>
                    </div>
                    <span className="spacer" />
                    {e.outcome !== "ok" && <Badge tone="bad">{e.outcome}</Badge>}
                  </li>
                ))}
              </ul>
            )}
          </section>
        )}
      </div>
    </>
  );
}
