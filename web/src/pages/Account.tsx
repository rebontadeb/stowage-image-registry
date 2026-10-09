import { useState } from "react";
import { api } from "../api";
import { useAction, useTitle } from "../hooks";
import { useSession } from "../session";
import { useToast } from "../components/toast";
import { Alert, Badge, Field, PageHead, RoleBadge } from "../components/ui";

/** Change-password form used by the account page and the forced first-sign-in screen. */
export function PasswordForm({ onDone }: { onDone: () => void }) {
  const [cur, setCur] = useState("");
  const [next, setNext] = useState("");
  const [again, setAgain] = useState("");
  const act = useAction();
  const toast = useToast();
  const mismatch = again !== "" && again !== next;

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (mismatch) return;
    if (await act.run(() => api.changePassword(cur, next))) {
      toast.success("Password changed. Other devices were signed out.");
      setCur(""); setNext(""); setAgain("");
      onDone();
    }
  };

  return (
    <form onSubmit={submit}>
      <Field label="Current password"><input className="input" type="password" value={cur} onChange={(e) => setCur(e.target.value)} autoComplete="current-password" required /></Field>
      <Field label="New password" hint="12–72 characters, not containing your username.">
        <input className="input" type="password" value={next} onChange={(e) => setNext(e.target.value)} autoComplete="new-password" required minLength={12} maxLength={72} />
      </Field>
      <Field label="Repeat new password" error={mismatch ? "Passwords do not match." : undefined}>
        <input className="input" type="password" value={again} onChange={(e) => setAgain(e.target.value)} autoComplete="new-password" required aria-invalid={mismatch} />
      </Field>
      <Alert>{act.error}</Alert>
      <button className="btn" disabled={act.busy || mismatch}>{act.busy ? "Saving…" : "Change password"}</button>
    </form>
  );
}

export function Account() {
  const s = useSession();
  const me = s.me!;
  useTitle("Your account");
  return (
    <>
      <PageHead title="Your account" />
      <div className="grid two">
        <section className="card" aria-labelledby="prof">
          <h2 id="prof">Profile</h2>
          <dl className="kv">
            <dt>Username</dt><dd className="mono">{me.username}</dd>
            <dt>Name</dt><dd>{me.displayName || "—"}</dd>
            <dt>Role</dt><dd><RoleBadge role={me.role} /></dd>
            <dt>Sign-in</dt><dd>{me.source === "oidc" ? <Badge tone="info">Single sign-on</Badge> : "Local password"}</dd>
            <dt>Registries</dt><dd>{me.role === "admin" ? "All" : me.allRegistries ? "All" : me.registries.length ? me.registries.join(", ") : "None assigned"}</dd>
          </dl>
        </section>
        <section className="card" aria-labelledby="pw">
          <h2 id="pw">Password</h2>
          {me.source === "local" ? <PasswordForm onDone={() => {}} /> : <p className="muted">Your password is managed by your identity provider.</p>}
        </section>
      </div>
    </>
  );
}
