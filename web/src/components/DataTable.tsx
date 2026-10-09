import { useEffect, useId, useMemo, useState, type ReactNode } from "react";
import { Skeleton } from "./ui";

export interface Column<T> {
  key: string;
  header: string;
  render: (row: T) => ReactNode;
  /** Value used for sorting; omit to make the column unsortable. */
  sort?: (row: T) => string | number | null;
  align?: "right";
  className?: string;
}

/** Sortable, paginated table with keyboard-accessible headers and optional row navigation. */
export function DataTable<T>({ columns, rows, rowKey, caption, loading, empty, onRowOpen, initialSort, pageSizes = [10, 25, 50], resetKey, roomy }: {
  columns: Column<T>[]; rows: T[]; rowKey: (r: T) => string; caption: string; loading?: boolean; empty: ReactNode;
  onRowOpen?: (r: T) => void; initialSort?: { key: string; dir: "asc" | "desc" }; pageSizes?: number[];
  /** Change this to jump back to page 1 (e.g. when filters change). */
  resetKey?: string;
  /** More padding per row: for short lists where each row is the main thing on the page. */
  roomy?: boolean;
}) {
  const [sort, setSort] = useState(initialSort);
  const [size, setSize] = useState(pageSizes[0]);
  const [page, setPage] = useState(0);
  const sortId = useId();
  useEffect(() => setPage(0), [resetKey, size]);

  const sorted = useMemo(() => {
    const col = columns.find((c) => c.key === sort?.key);
    if (!col?.sort) return rows;
    const dir = sort!.dir === "asc" ? 1 : -1;
    return [...rows].sort((a, b) => {
      const x = col.sort!(a), y = col.sort!(b);
      if (x === y) return 0;
      if (x === null) return 1; // nulls last in both directions
      if (y === null) return -1;
      return (x < y ? -1 : 1) * dir;
    });
  }, [rows, sort, columns]);

  const pages = Math.max(1, Math.ceil(sorted.length / size));
  const cur = Math.min(page, pages - 1);
  const slice = sorted.slice(cur * size, cur * size + size);

  const toggle = (key: string) => setSort((s) => (s?.key === key ? { key, dir: s.dir === "asc" ? "desc" : "asc" } : { key, dir: "asc" }));

  if (loading && !rows.length) return <Skeleton rows={4} />;
  if (!rows.length) return <>{empty}</>;

  return (
    <>
      {columns.some((c) => c.sort) && (
        <div className="sort-mobile">
          <label className="sr-only" htmlFor={sortId}>Sort by</label>
          <select id={sortId} className="input" value={sort?.key ?? ""} onChange={(e) => setSort({ key: e.target.value, dir: sort?.dir ?? "asc" })}>
            {!sort && <option value="">Sort by…</option>}
            {columns.filter((c) => c.sort).map((c) => <option key={c.key} value={c.key}>Sort by {c.header}</option>)}
          </select>
          <button type="button" className="btn secondary sm" disabled={!sort} onClick={() => sort && setSort({ ...sort, dir: sort.dir === "asc" ? "desc" : "asc" })}
            aria-label={sort?.dir === "desc" ? "Descending, switch to ascending" : "Ascending, switch to descending"}>{sort?.dir === "desc" ? "▼ Desc" : "▲ Asc"}</button>
        </div>
      )}
      <div className="table-wrap" tabIndex={0} role="region" aria-label={caption}>
        <table className={`table stack${roomy ? " roomy" : ""}`} role="table">
          <caption className="sr-only">{caption}</caption>
          <thead>
            <tr role="row">
              {columns.map((c) => (
                <th key={c.key} scope="col" role="columnheader" className={`${c.align === "right" ? "r" : ""} ${c.className ?? ""}`}
                  aria-sort={sort?.key === c.key ? (sort.dir === "asc" ? "ascending" : "descending") : c.sort ? "none" : undefined}>
                  {c.sort ? (
                    <button type="button" onClick={() => toggle(c.key)}>
                      {c.header}<span aria-hidden="true">{sort?.key === c.key ? (sort.dir === "asc" ? " ▲" : " ▼") : ""}</span>
                    </button>
                  ) : c.header || <span className="sr-only">Actions</span>}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {slice.map((r) => (
              <tr key={rowKey(r)} role="row" className={onRowOpen ? "click" : undefined}
                onClick={onRowOpen ? (e) => { if (!(e.target as HTMLElement).closest("a,button,input,select,label")) onRowOpen(r); } : undefined}>
                {columns.map((c) => <td key={c.key} role="cell" data-label={c.header} className={`${c.align === "right" ? "r" : ""} ${c.className ?? ""}`}>{c.render(r)}</td>)}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="pager">
        <span className="num">{sorted.length === 0 ? "0" : `${cur * size + 1}–${Math.min(sorted.length, cur * size + size)}`} of {sorted.length}</span>
        <span className="spacer" />
        <label>Rows <select className="input" style={{ width: "auto", padding: "2px 6px" }} value={size} onChange={(e) => setSize(Number(e.target.value))}>
          {pageSizes.map((n) => <option key={n}>{n}</option>)}
        </select></label>
        <button className="btn secondary sm" disabled={cur === 0} onClick={() => setPage(cur - 1)}>Previous</button>
        <span className="num" aria-live="polite">Page {cur + 1} / {pages}</span>
        <button className="btn secondary sm" disabled={cur >= pages - 1} onClick={() => setPage(cur + 1)}>Next</button>
      </div>
    </>
  );
}
