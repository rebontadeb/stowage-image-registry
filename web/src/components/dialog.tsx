import { createContext, useCallback, useContext, useEffect, useId, useRef, useState, type ReactNode } from "react";

const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

/** Modal dialog: traps focus, closes on Escape / backdrop, restores focus on close. */
export function Dialog({ title, onClose, children, footer, wide, xl, dismissible = true }: {
  title: string; onClose: () => void; children: ReactNode; footer?: ReactNode; wide?: boolean; xl?: boolean; dismissible?: boolean;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const titleId = useId();

  useEffect(() => {
    const prev = document.activeElement as HTMLElement | null;
    const el = ref.current!;
    const first = el.querySelector<HTMLElement>("[data-autofocus]") ?? el.querySelector<HTMLElement>(FOCUSABLE);
    first?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape" && dismissible) { e.stopPropagation(); onClose(); return; }
      if (e.key !== "Tab") return;
      const items = [...el.querySelectorAll<HTMLElement>(FOCUSABLE)];
      if (!items.length) return;
      const a = items[0], z = items[items.length - 1];
      if (e.shiftKey && document.activeElement === a) { e.preventDefault(); z.focus(); }
      else if (!e.shiftKey && document.activeElement === z) { e.preventDefault(); a.focus(); }
    };
    document.addEventListener("keydown", onKey, true);
    document.body.style.overflow = "hidden";
    return () => { document.removeEventListener("keydown", onKey, true); document.body.style.overflow = ""; prev?.focus?.(); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div className="overlay" onMouseDown={(e) => { if (dismissible && e.target === e.currentTarget) onClose(); }}>
      <div ref={ref} className={`dialog${wide ? " wide" : ""}${xl ? " xl" : ""}`} role="dialog" aria-modal="true" aria-labelledby={titleId}>
        <div className="dlg-head"><h2 id={titleId}>{title}</h2></div>
        <div className="body">{children}</div>
        {footer && <div className="dlg-foot">{footer}</div>}
      </div>
    </div>
  );
}

export interface ConfirmOptions {
  title: string;
  body?: ReactNode;
  confirmLabel?: string;
  danger?: boolean;
  /** The user must type this exact text to enable the confirm button. */
  requireText?: string;
}

type Confirm = (o: ConfirmOptions) => Promise<boolean>;
const Ctx = createContext<Confirm>(async () => false);
export const useConfirm = () => useContext(Ctx);

export function ConfirmProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<{ o: ConfirmOptions; done: (v: boolean) => void }>();
  const confirm = useCallback<Confirm>((o) => new Promise((done) => setState({ o, done })), []);
  const finish = (v: boolean) => { state?.done(v); setState(undefined); };
  return (
    <Ctx.Provider value={confirm}>
      {children}
      {state && <ConfirmDialog o={state.o} onDone={finish} />}
    </Ctx.Provider>
  );
}

function ConfirmDialog({ o, onDone }: { o: ConfirmOptions; onDone: (v: boolean) => void }) {
  const [typed, setTyped] = useState("");
  const ok = !o.requireText || typed === o.requireText;
  return (
    <Dialog title={o.title} onClose={() => onDone(false)} footer={
      <>
        <button className="btn secondary" onClick={() => onDone(false)}>Cancel</button>
        <button className={`btn ${o.danger ? "danger solid" : ""}`} disabled={!ok} onClick={() => onDone(true)}>{o.confirmLabel ?? "Confirm"}</button>
      </>
    }>
      {o.body && <div style={{ marginBottom: o.requireText ? 14 : 0 }}>{o.body}</div>}
      {o.requireText && (
        <label className="field" style={{ marginBottom: 0 }}>
          <span className="label">Type <code>{o.requireText}</code> to confirm</span>
          <input className="input" data-autofocus value={typed} onChange={(e) => setTyped(e.target.value)} autoComplete="off" spellCheck={false} />
        </label>
      )}
    </Dialog>
  );
}
