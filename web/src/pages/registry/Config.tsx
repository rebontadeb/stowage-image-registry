import { useEffect, useState } from "react";
import { api } from "../../api";
import { useAction, useLoad } from "../../hooks";
import { useConfirm } from "../../components/dialog";
import { useToast } from "../../components/toast";
import { Alert, Badge, Field } from "../../components/ui";
import type { TabProps } from "../RegistryDetail";

const toLines = (env: Record<string, string>) => Object.entries(env).map(([k, v]) => `${k}=${v}`).join("\n");

function parseEnv(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const i = line.indexOf("=");
    if (i < 1) throw new Error(`Bad line "${line}": expected KEY=value`);
    out[line.slice(0, i).trim()] = line.slice(i + 1);
  }
  return out;
}

export function Config({ reg, reload }: TabProps) {
  const confirm = useConfirm();
  const toast = useToast();
  const cfg = useLoad(() => api.config(reg.name), [reg.name]);
  const [config, setConfig] = useState("");
  const [env, setEnv] = useState("");
  const act = useAction();

  useEffect(() => { if (cfg.data) { setConfig(cfg.data.config); setEnv(toLines(cfg.data.env)); } }, [cfg.data]);

  const save = async (reset: boolean) => {
    if (await act.run(async () => { await api.setConfig(reg.name, { config: reset ? "" : config, env: parseEnv(env) }); })) {
      toast.success(reset ? "Configuration reset to default" : "Configuration saved");
      cfg.reload(); reload();
    }
  };
  const resetCfg = async () => {
    if (await confirm({ title: "Reset config.yml to the default?", confirmLabel: "Reset", body: <p>Your customised config.yml is discarded. Environment overrides are kept.</p> })) save(true);
  };

  return (
    <section className="card" aria-labelledby="cfg">
      <div className="row"><h2 id="cfg" style={{ margin: 0 }}>Registry configuration</h2>{cfg.data && <Badge tone={cfg.data.custom ? "info" : "neutral"}>{cfg.data.custom ? "Custom" : "Default"}</Badge>}</div>
      <p className="muted" style={{ marginTop: 8 }}>Authentication, TLS, the storage path and the listen port are managed for you and cannot be changed here.</p>
      <Alert>{cfg.error}</Alert>
      <Field label="config.yml"><textarea className="input" style={{ minHeight: 260 }} value={config} onChange={(e) => setConfig(e.target.value)} spellCheck={false} /></Field>
      <Field label="Environment overrides" hint="One REGISTRY_* variable per line, e.g. REGISTRY_LOG_LEVEL=debug. Values may be sensitive; they are visible to operators only.">
        <textarea className="input" value={env} onChange={(e) => setEnv(e.target.value)} spellCheck={false} autoComplete="off" />
      </Field>
      <p className="muted">Saving restarts the registry briefly. Stored images are kept.</p>
      <Alert>{act.error}</Alert>
      <div className="row">
        <button className="btn" disabled={act.busy} onClick={() => save(false)}>{act.busy ? "Applying…" : "Save configuration"}</button>
        <button className="btn secondary" disabled={act.busy || !cfg.data?.custom} onClick={resetCfg}>Reset config to default</button>
      </div>
    </section>
  );
}
