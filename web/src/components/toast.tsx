import { createContext, useCallback, useContext, useRef, useState, type ReactNode } from "react";

interface Toast { id: number; kind: "success" | "error"; text: string }
interface Api { success: (t: string) => void; error: (t: string) => void }
const Ctx = createContext<Api>({ success() {}, error() {} });
export const useToast = () => useContext(Ctx);

export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<Toast[]>([]);
  const seq = useRef(0);
  const dismiss = (id: number) => setItems((l) => l.filter((t) => t.id !== id));
  const push = useCallback((kind: Toast["kind"], text: string) => {
    const id = ++seq.current;
    setItems((l) => [...l.slice(-3), { id, kind, text }]);
    setTimeout(() => dismiss(id), kind === "error" ? 9000 : 4500);
  }, []);
  const api = useRef<Api>({ success: (t) => push("success", t), error: (t) => push("error", t) }).current;
  return (
    <Ctx.Provider value={api}>
      {children}
      <div className="toasts" role="region" aria-label="Notifications" aria-live="polite">
        {items.map((t) => (
          <div key={t.id} className={`toast ${t.kind}`} role={t.kind === "error" ? "alert" : "status"}>
            <span>{t.text}</span>
            <button className="btn ghost sm" onClick={() => dismiss(t.id)} aria-label="Dismiss notification">✕</button>
          </div>
        ))}
      </div>
    </Ctx.Provider>
  );
}
