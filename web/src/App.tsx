import { useEffect, useRef, useState, type ReactNode } from "react";
import { SessionProvider, useSession } from "./session";
import { ToastProvider } from "./components/toast";
import { ConfirmProvider } from "./components/dialog";
import { Alert, PageHead } from "./components/ui";
import { href, useRoute } from "./router";
import { useMedia } from "./hooks";
import { IconAccounts, IconAudit, IconChevronsLeft, IconChevronsRight, IconClose, IconDashboard, IconMenu, IconRegistries, IconShield, IconSignOut } from "./components/icons";
import { getTheme, setTheme, type Theme } from "./theme";
import { Login } from "./pages/Login";
import { PasswordForm } from "./pages/Account";
import { Dashboard } from "./pages/Dashboard";
import { Registries } from "./pages/Registries";
import { RegistryDetail } from "./pages/RegistryDetail";
import { Audit } from "./pages/Audit";
import { Accounts } from "./pages/Accounts";
import { Account } from "./pages/Account";
import { SecurityTools } from "./pages/SecurityTools";

export function App() {
  return (
    <SessionProvider>
      <ToastProvider>
        <ConfirmProvider>
          <Gate />
        </ConfirmProvider>
      </ToastProvider>
    </SessionProvider>
  );
}

function Gate() {
  const s = useSession();
  if (s.loading) return <div className="login-wrap" aria-busy="true"><span className="muted">Loading…</span></div>;
  if (!s.me) return <Login />;
  if (s.me.mustChangePassword) return <ForcedChange />;
  return <Shell />;
}

function ForcedChange() {
  const s = useSession();
  return (
    <div className="login-wrap">
      <main className="login-card">
        <div className="brand"><span className="logo" aria-hidden="true">S</span>Stowage</div>
        <h1 style={{ fontSize: 18, marginBottom: 6 }}>Choose a new password</h1>
        <p className="muted">Hi {s.me!.displayName || s.me!.username}. You need to set your own password before continuing.</p>
        <PasswordForm onDone={() => s.refresh()} />
        <button className="btn ghost sm" style={{ marginTop: 10 }} onClick={() => s.logout()}>Sign out</button>
      </main>
    </div>
  );
}

const NAV_KEY = "rui-nav";

function Shell() {
  const s = useSession();
  const route = useRoute();
  const mobile = useMedia("(max-width: 900px)");
  const [open, setOpen] = useState(false); // drawer, phones and tablets
  const [collapsed, setCollapsed] = useState(() => {
    try { return localStorage.getItem(NAV_KEY) === "collapsed"; } catch { return false; }
  });
  const [theme, setThemeState] = useState<Theme>(getTheme);
  const menuBtn = useRef<HTMLButtonElement>(null);
  const closeBtn = useRef<HTMLButtonElement>(null);
  const area = route.parts[0] ?? "";
  const drawerOpen = open && mobile;

  const toggleCollapsed = () => setCollapsed((c) => {
    const next = !c;
    try { localStorage.setItem(NAV_KEY, next ? "collapsed" : "expanded"); } catch { /* storage unavailable */ }
    return next;
  });
  const restoreFocus = useRef(false);
  const closeDrawer = (restore = true) => { restoreFocus.current = restore; setOpen(false); };
  // Focus the menu button once the page is no longer inert; doing it in the click handler would be too early.
  useEffect(() => { if (!drawerOpen && restoreFocus.current) { restoreFocus.current = false; menuBtn.current?.focus(); } }, [drawerOpen]);

  // Move focus to the page heading after navigation so screen readers announce the new page.
  useEffect(() => {
    setOpen(false);
    const t = setTimeout(() => document.querySelector<HTMLElement>("[data-page-title]")?.focus({ preventScroll: true }), 50);
    return () => clearTimeout(t);
  }, [route.parts.join("/")]);

  // An open drawer behaves like a modal: Escape closes it, the page behind cannot scroll or take focus.
  useEffect(() => {
    if (!drawerOpen) return;
    closeBtn.current?.focus();
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") closeDrawer(); };
    document.addEventListener("keydown", onKey);
    document.body.style.overflow = "hidden";
    return () => { document.removeEventListener("keydown", onKey); document.body.style.overflow = ""; };
  }, [drawerOpen]);
  useEffect(() => { if (!mobile) setOpen(false); }, [mobile]);

  const nav = [
    { to: "", label: "Dashboard", icon: <IconDashboard /> },
    { to: "registries", label: "Registries", icon: <IconRegistries /> },
  ];
  const admin = [
    { to: "audit", label: "Audit log", icon: <IconAudit /> },
    { to: "accounts", label: "Accounts & access", icon: <IconAccounts /> },
    ...(s.config?.security ? [{ to: "security", label: "Security tools", icon: <IconShield /> }] : []),
  ];
  const tip = collapsed && !mobile;
  const link = (n: { to: string; label: string; icon: ReactNode }) => (
    <a key={n.to} href={n.to ? href(n.to) : "#/"} aria-current={area === n.to ? "page" : undefined} title={tip ? n.label : undefined}>
      {n.icon}<span className="nav-label">{n.label}</span>
    </a>
  );

  let page;
  switch (area) {
    case "": page = <Dashboard />; break;
    case "registries": page = route.parts[1] ? <RegistryDetail key={route.parts[1]} name={route.parts[1]} tab={route.parts[2]} sub={route.parts[3]} /> : <Registries />; break;
    case "audit": page = s.isAdmin ? <Audit /> : <Forbidden />; break;
    case "accounts": page = s.isAdmin ? <Accounts /> : <Forbidden />; break;
    case "security": page = s.isAdmin && s.config?.security ? <SecurityTools /> : <Forbidden />; break;
    case "account": page = <Account />; break;
    default: page = <PageHead title="Page not found" subtitle={<a href="#/">Back to the dashboard</a>} />;
  }

  const initials = (s.me!.displayName || s.me!.username).slice(0, 2).toUpperCase();
  const themeSelect = (id: string, cls: string) => (
    <>
      <label className="sr-only" htmlFor={id}>Theme</label>
      <select id={id} className={`input ${cls}`} value={theme} onChange={(e) => { const t = e.target.value as Theme; setTheme(t); setThemeState(t); }}>
        <option value="system">System theme</option><option value="light">Light</option><option value="dark">Dark</option>
      </select>
    </>
  );

  return (
    <div className={`shell${collapsed ? " collapsed" : ""}`}>
      <a className="skip" href="#main" onClick={(e) => { e.preventDefault(); document.getElementById("main")?.focus(); }}>Skip to content</a>
      <aside id="sidebar" className={`sidebar${drawerOpen ? " open" : ""}`} inert={mobile && !drawerOpen} aria-label="Navigation">
        <div className="brand">
          <span className="logo" aria-hidden="true">S</span><span className="nav-label">Stowage</span>
          <span className="spacer" />
          <button ref={closeBtn} className="icon-btn drawer-only" aria-label="Close navigation" onClick={() => closeDrawer()}><IconClose /></button>
        </div>
        <nav className="nav" aria-label="Main">
          {nav.map(link)}
          {s.isAdmin && <><div className="section"><span className="nav-label">Administration</span></div>{admin.map(link)}</>}
        </nav>
        <div className="foot">
          <div className="drawer-only drawer-tools">
            <a className="drawer-user" href={href("account")}><span className="avatar" aria-hidden="true">{initials}</span><span><strong>{s.me!.displayName || s.me!.username}</strong><br /><span className="muted-light">{s.me!.role}</span></span></a>
            {themeSelect("theme-drawer", "")}
            <button className="btn secondary sm" onClick={() => s.logout()}><IconSignOut /> Sign out</button>
          </div>
          <div className="who desktop-only">Signed in as<br /><strong>{s.me!.username}</strong> · {s.me!.role}</div>
          <button className="collapse-btn desktop-only" onClick={toggleCollapsed} aria-expanded={!collapsed} aria-controls="sidebar" title={collapsed ? "Expand navigation" : undefined}>
            {collapsed ? <IconChevronsRight /> : <IconChevronsLeft />}<span className="nav-label">{collapsed ? "Expand navigation" : "Collapse navigation"}</span>
          </button>
        </div>
      </aside>
      {drawerOpen && <div className="scrim" onClick={() => closeDrawer()} aria-hidden="true" />}
      <div className="content" inert={drawerOpen}>
        <header className="topbar">
          <button ref={menuBtn} className="icon-btn menu-btn" aria-label="Open navigation" aria-expanded={drawerOpen} aria-controls="sidebar" onClick={() => setOpen(true)}><IconMenu /></button>
          <span className="topbar-brand">Stowage</span>
          <span className="spacer" />
          {themeSelect("theme", "hide-sm theme-select")}
          <a className="user-chip" href={href("account")} aria-label={`Your account, ${s.me!.username}`}>
            <span className="avatar" aria-hidden="true">{initials}</span>
            <span className="hide-sm">{s.me!.displayName || s.me!.username}</span>
          </a>
          <button className="btn secondary sm hide-sm" onClick={() => s.logout()}>Sign out</button>
        </header>
        <main id="main" tabIndex={-1}>{page}</main>
        <footer className="app-footer">
          <div className="app-footer-id">
            <span className="logo" aria-hidden="true">S</span>
            <span><strong>Stowage</strong> <span className="muted">· Private container registries for your tenants</span></span>
          </div>
          <div className="app-footer-links">
            {s.me!.version && <span title="Build version">Version <span className="mono">{s.me!.version}</span></span>}
            <a href="https://github.com/rebontadeb/stowage-image-registry#readme" target="_blank" rel="noopener noreferrer">Documentation<span className="sr-only"> (opens in a new tab)</span></a>
            <a href="https://github.com/rebontadeb/stowage-image-registry" target="_blank" rel="noopener noreferrer">Source<span className="sr-only"> (opens in a new tab)</span></a>
          </div>
        </footer>
      </div>
    </div>
  );
}

function Forbidden() {
  return <><PageHead title="Not allowed" /><Alert kind="warn">Your role does not include this area.</Alert></>;
}
