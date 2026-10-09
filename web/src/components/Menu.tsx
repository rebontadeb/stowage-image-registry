import { useEffect, useId, useLayoutEffect, useRef, useState } from "react";

export interface MenuItem { label: string; onSelect: () => void; danger?: boolean; disabled?: boolean }

/** A small action menu ("more" button) with keyboard support: Enter/Space/ArrowDown open it, arrows move, Escape closes. */
export function Menu({ label, items, text }: { label: string; items: MenuItem[]; text?: string }) {
  const [open, setOpen] = useState(false);
  const [flip, setFlip] = useState(false); // open towards the right when the default (right-aligned) would leave the screen
  const btn = useRef<HTMLButtonElement>(null);
  const list = useRef<HTMLDivElement>(null);
  const id = useId();

  useLayoutEffect(() => {
    if (!open || !list.current) return;
    setFlip(false);
    const r = list.current.getBoundingClientRect();
    if (r.left < 8) setFlip(true);
  }, [open]);

  useEffect(() => {
    if (!open) return;
    list.current?.querySelector<HTMLElement>('[role="menuitem"]:not(:disabled)')?.focus();
    const onDown = (e: MouseEvent) => {
      if (!list.current?.contains(e.target as Node) && !btn.current?.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", onDown);
    return () => document.removeEventListener("mousedown", onDown);
  }, [open]);

  const close = (refocus = true) => { setOpen(false); if (refocus) btn.current?.focus(); };
  const onKey = (e: React.KeyboardEvent) => {
    const els = [...(list.current?.querySelectorAll<HTMLElement>('[role="menuitem"]:not(:disabled)') ?? [])];
    const i = els.indexOf(document.activeElement as HTMLElement);
    if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); close(); }
    else if (e.key === "ArrowDown") { e.preventDefault(); els[(i + 1) % els.length]?.focus(); }
    else if (e.key === "ArrowUp") { e.preventDefault(); els[(i - 1 + els.length) % els.length]?.focus(); }
    else if (e.key === "Home") { e.preventDefault(); els[0]?.focus(); }
    else if (e.key === "End") { e.preventDefault(); els[els.length - 1]?.focus(); }
    else if (e.key === "Tab") setOpen(false);
  };

  return (
    <span className="menu">
      <button ref={btn} type="button" className={`btn secondary sm${text ? "" : " icon-only"}`} aria-haspopup="menu" aria-expanded={open} aria-controls={open ? id : undefined}
        aria-label={label} onClick={() => setOpen(!open)}
        onKeyDown={(e) => { if (e.key === "ArrowDown" && !open) { e.preventDefault(); setOpen(true); } }}>
        {text ?? "⋯"}
      </button>
      {open && (
        <div id={id} ref={list} className={`menu-list${flip ? " flip" : ""}`} role="menu" aria-label={label} onKeyDown={onKey}>
          {items.map((it) => (
            <button key={it.label} type="button" role="menuitem" className={it.danger ? "danger" : ""} disabled={it.disabled}
              onClick={() => { close(false); it.onSelect(); }}>{it.label}</button>
          ))}
        </div>
      )}
    </span>
  );
}
