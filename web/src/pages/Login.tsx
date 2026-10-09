import { useState } from "react";
import { useSession } from "../session";
import { useRoute } from "../router";
import { useAction, useTitle } from "../hooks";
import { Alert, Field } from "../components/ui";

export function Login() {
  const s = useSession();
  const route = useRoute();
  const act = useAction();
  const [user, setUser] = useState("");
  const [pass, setPass] = useState("");
  useTitle("Sign in");
  const redirectError = route.parts[0] === "login" ? route.query.get("error") ?? undefined : undefined;
  const local = s.config?.localLogin ?? true;

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (await act.run(() => s.login(user, pass))) {
      if (location.hash.startsWith("#/login")) location.hash = "#/";
    }
  };

  return (
    <div className="login-wrap">
      <main className="login-card">
        <div className="brand"><span className="logo" aria-hidden="true">S</span>Stowage</div>
        <h1 style={{ fontSize: 20, marginBottom: 4 }}>Sign in</h1>
        <p className="muted">Private container registries for each of your tenants.</p>
        <Alert>{redirectError}</Alert>
        {local && (
          <form onSubmit={submit}>
            <Field label="Username"><input className="input" value={user} onChange={(e) => setUser(e.target.value)} autoComplete="username" required autoFocus /></Field>
            <Field label="Password"><input className="input" type="password" value={pass} onChange={(e) => setPass(e.target.value)} autoComplete="current-password" required /></Field>
            <Alert>{act.error}</Alert>
            <button className="btn" style={{ width: "100%", justifyContent: "center" }} disabled={act.busy}>{act.busy ? "Signing in…" : "Sign in"}</button>
          </form>
        )}
        {s.config?.oidc && (
          <>
            {local && <div className="divider">or</div>}
            <a className="btn secondary" style={{ width: "100%", justifyContent: "center" }} href="/api/auth/oidc/login">Sign in with {s.config.oidcName}</a>
          </>
        )}
        {!local && !s.config?.oidc && <Alert kind="warn">Sign-in is not configured. Contact an administrator.</Alert>}
      </main>
    </div>
  );
}
