export type Theme = "system" | "light" | "dark";
const KEY = "rui-theme";

export function getTheme(): Theme {
  try { const v = localStorage.getItem(KEY); if (v === "light" || v === "dark") return v; } catch { /* storage unavailable */ }
  return "system";
}

export function setTheme(t: Theme) {
  try { t === "system" ? localStorage.removeItem(KEY) : localStorage.setItem(KEY, t); } catch { /* ignore */ }
  applyTheme(t);
}

export function applyTheme(t: Theme = getTheme()) {
  if (t === "system") document.documentElement.removeAttribute("data-theme");
  else document.documentElement.setAttribute("data-theme", t);
}
