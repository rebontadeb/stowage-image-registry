import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { api, newSessionEpoch, setUnauthorizedHandler, type AuthConfig, type Me } from "./api";

interface Session {
  me: Me | null;
  config: AuthConfig | null;
  loading: boolean;
  isAdmin: boolean;
  canOperate: boolean;
  login: (u: string, p: string) => Promise<void>;
  logout: () => Promise<void>;
  refresh: () => Promise<void>;
}

const Ctx = createContext<Session>(null as unknown as Session);
export const useSession = () => useContext(Ctx);

export function SessionProvider({ children }: { children: ReactNode }) {
  const [me, setMe] = useState<Me | null>(null);
  const [config, setConfig] = useState<AuthConfig | null>(null);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    try { setMe(await api.me()); } catch { setMe(null); }
  }, []);

  useEffect(() => {
    setUnauthorizedHandler(() => { newSessionEpoch(); setMe(null); });
    (async () => {
      const [c] = await Promise.allSettled([api.authConfig(), refresh()]);
      if (c.status === "fulfilled") setConfig(c.value);
      setLoading(false);
    })();
    return () => setUnauthorizedHandler(undefined);
  }, [refresh]);

  const value = useMemo<Session>(() => ({
    me, config, loading,
    isAdmin: me?.role === "admin",
    canOperate: me?.role === "admin" || me?.role === "operator",
    login: async (u, p) => { const m = await api.login(u, p); newSessionEpoch(); setMe(m); },
    logout: async () => { try { await api.logout(); } finally { newSessionEpoch(); setMe(null); location.hash = "#/"; } },
    refresh,
  }), [me, config, loading, refresh]);

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}
