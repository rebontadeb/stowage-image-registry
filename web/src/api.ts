export type State = "running" | "starting" | "stopped" | "missing";
export type Role = "admin" | "operator" | "viewer";

export interface Reg {
  name: string; customer: string; image: string; hostPort: number; storageSize: string; createdAt: string;
  state: State; endpoint: string; host: string; url: string; tls: boolean; customConfig: boolean;
}
export interface FleetItem extends Reg { usedBytes: number | null; scannedImages: number; criticalVulns: number; highVulns: number }
export interface FleetSummary { scannedImages: number; criticalVulns: number; highVulns: number; registriesWithCritical: number; total: number; running: number; starting: number; stopped: number; missing: number; tls: number; noTLS: number; usedBytes: number }
export interface Fleet { summary: FleetSummary; registries: FleetItem[] }

export interface Me {
  id: number; username: string; displayName: string; role: Role; source: "local" | "oidc";
  allRegistries: boolean; registries: string[]; mustChangePassword: boolean; version?: string;
}
export interface AuthConfig { localLogin: boolean; oidc: boolean; oidcName?: string; security?: boolean }
export interface Account {
  id: number; username: string; displayName: string; role: Role; source: "local" | "oidc"; disabled: boolean;
  mustChangePassword: boolean; allRegistries: boolean; registries: string[]; createdAt: string; lastLogin: string;
}
export interface AuditEntry {
  id: number; time: string; actor: string; actorRole: string; action: string; target: string;
  detail?: Record<string, string>; outcome: "ok" | "denied" | "error"; ip: string;
}
export interface AuditQuery { actor?: string; action?: string; target?: string; outcome?: string; since?: string; until?: string; before?: number; limit?: number }

export interface RepoSummary { name: string; tags: number }
export interface TagInfo { tag: string; digest: string; kind: "image" | "signature" }
export interface GCResult { output: string; bytesBefore: number; bytesAfter: number }
export interface TLSInfo { enabled: boolean; notAfter?: string; dnsNames?: string[]; subject?: string; selfSigned?: boolean }
export interface ConfigView { config: string; custom: boolean; env: Record<string, string> }

// ---- security: scans, SBOMs, signatures, compliance ----
export type ScanKind = "vuln" | "sbom" | "sig" | "oval";
export type ScanStatus = "queued" | "running" | "done" | "failed";
export interface ScanView {
  digest: string; repo: string; kind: ScanKind; status: ScanStatus; error?: string; tool?: string;
  summary: Record<string, unknown>; queued: string; started: string; finished: string; by?: string;
}
export interface VulnSummary { critical: number; high: number; medium: number; low: number; negligible: number; unknown: number; total: number; fixable: number; dbBuilt?: string }
export interface Vuln { id: string; severity: string; package: string; version: string; type: string; fixedIn: string[]; fixState: string; url?: string; score?: number }
export interface VulnReport { summary: VulnSummary; tool: string; vulns: Vuln[] }
export interface Component { name: string; version: string; type: string; purl: string; licenses?: string[] }
export interface SBOMSummary { packages: number; files: number; byType: Record<string, number>; format: string }
export interface SBOMReport { summary: SBOMSummary; tool: string; components: Component[] }
export type SigState = "signed" | "unsigned" | "invalid" | "unverified";
export interface SigResult { status: SigState; key?: string; attempts: { key: string; status: string }[] }
export interface OVALFinding { definition: string; advisory: string; title: string; severity: string; cves: string[]; url?: string }
export interface OVALSummary { applicable: boolean; reason?: string; os?: string; content?: string; definitions: number; vulnerable: number; critical: number; important: number; moderate: number; low: number }
export interface OVALReport { summary: OVALSummary; findings: OVALFinding[] }
export interface TrustKey { id: number; label: string; publicKey: string; fingerprint: string; own: boolean; created: string }
export interface SigningInfo { signingKey: { publicKey: string; fingerprint: string; created: string } | null; trustedKeys: TrustKey[] }
export interface SCAPContent { name: string; kind: string; filename: string; sha256: string; size: number; source: string; addedBy: string; added: string }
export interface SecurityStatus { enabled: boolean; images: { Syft: string; Grype: string; Cosign: string; OpenSCAP: string }; workers: number; content: SCAPContent[] }

// ---- adding images ----
export type TransferStatus = "queued" | "running" | "done" | "failed";
export interface FixPlan { packages: string[]; all: boolean; manager: "dnf" | "apk"; newTag: string }
export interface TransferView {
  id: string; kind: "import" | "upload" | "fix" | "rebase"; registry: string; repo: string; tag: string; source?: string;
  status: TransferStatus; error?: string; digest?: string; done: number; total: number;
  queued: string; started: string; finished: string; by?: string;
}
export interface ImportBody {
  source: string; username?: string; password?: string; skipTLS?: boolean; allPlatforms?: boolean;
  repo: string; tag: string; overwrite?: boolean; scan?: boolean;
}

export class ApiError extends Error {
  constructor(message: string, public status: number, public code?: string) { super(message); }
}

let onUnauthorized: (() => void) | undefined;
export const setUnauthorizedHandler = (fn?: () => void) => { onUnauthorized = fn; };

// Bumped on every sign-in and sign-out. A 401 for a request that started under an earlier session
// must not sign out the current one (a slow request from the previous user would otherwise do so).
let epoch = 0;
export const newSessionEpoch = () => { epoch++; };

async function req<T>(method: string, path: string, body?: unknown): Promise<T> {
  const startedIn = epoch;
  const res = await fetch("/api" + path, {
    method, credentials: "same-origin",
    headers: body === undefined ? undefined : { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (res.status === 204) return undefined as T;
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    if (res.status === 401 && data.code === "unauthenticated" && startedIn === epoch) onUnauthorized?.();
    throw new ApiError(data.error ?? `HTTP ${res.status}`, res.status, data.code);
  }
  return data as T;
}

const r = (n: string) => `/registries/${encodeURIComponent(n)}`;
const qs = (o: Record<string, string | number | undefined>) => {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(o)) if (v !== undefined && v !== "") p.set(k, String(v));
  const s = p.toString();
  return s ? "?" + s : "";
};

export const api = {
  // session
  authConfig: () => req<AuthConfig>("GET", "/auth/config"),
  me: () => req<Me>("GET", "/auth/me"),
  login: (username: string, password: string) => req<Me>("POST", "/auth/login", { username, password }),
  logout: () => req<void>("POST", "/auth/logout"),
  changePassword: (current: string, next: string) => req<unknown>("POST", "/auth/password", { current, new: next }),

  // fleet & registries
  fleet: () => req<Fleet>("GET", "/fleet"),
  get: (n: string) => req<Reg>("GET", r(n)),
  create: (b: { name: string; customer: string; username?: string; password?: string }) => req<Reg>("POST", "/registries", b),
  start: (n: string) => req<Reg>("POST", `${r(n)}/start`),
  stop: (n: string) => req<Reg>("POST", `${r(n)}/stop`),
  remove: (n: string, keepData: boolean) => req<void>("DELETE", `${r(n)}${keepData ? "?keepData=true" : ""}`),
  usage: (n: string) => req<{ usedBytes: number }>("GET", `${r(n)}/usage`),
  repos: (n: string) => req<string[]>("GET", `${r(n)}/repositories`),
  repoSummaries: (n: string) => req<RepoSummary[]>("GET", `${r(n)}/repository-summaries`),
  deleteRepo: (n: string, repo: string) => req<{ tags: number; manifests: number }>("DELETE", `${r(n)}/repositories?repo=${encodeURIComponent(repo)}`),
  tags: (n: string, repo: string) => req<TagInfo[]>("GET", `${r(n)}/tags?repo=${encodeURIComponent(repo)}`),
  deleteTag: (n: string, repo: string, tag: string) =>
    req<{ deletedDigest: string }>("DELETE", `${r(n)}/tags?repo=${encodeURIComponent(repo)}&tag=${encodeURIComponent(tag)}`),
  gc: (n: string) => req<GCResult>("POST", `${r(n)}/gc`),
  users: (n: string) => req<{ users: string[] }>("GET", `${r(n)}/users`),
  setUser: (n: string, u: string, password: string) => req<unknown>("PUT", `${r(n)}/users/${encodeURIComponent(u)}`, { password }),
  removeUser: (n: string, u: string) => req<void>("DELETE", `${r(n)}/users/${encodeURIComponent(u)}`),
  tls: (n: string) => req<TLSInfo>("GET", `${r(n)}/tls`),
  setTLS: (n: string, b: { generate?: boolean; hosts?: string[]; cert?: string; key?: string }) => req<TLSInfo>("PUT", `${r(n)}/tls`, b),
  removeTLS: (n: string) => req<void>("DELETE", `${r(n)}/tls`),
  config: (n: string) => req<ConfigView>("GET", `${r(n)}/config`),
  setConfig: (n: string, b: { config: string; env: Record<string, string> }) => req<ConfigView>("PUT", `${r(n)}/config`, b),

  // security
  scans: (n: string, repo: string) => req<ScanView[]>("GET", `${r(n)}/scans?repo=${encodeURIComponent(repo)}`),
  startScan: (n: string, repo: string, ref: string, kinds: ScanKind[]) => req<{ digest: string; queued: string[] }>("POST", `${r(n)}/scans`, { repo, ref, kinds }),
  scanResult: <T>(n: string, repo: string, digest: string, kind: ScanKind) =>
    req<T>("GET", `${r(n)}/scans/result?repo=${encodeURIComponent(repo)}&digest=${encodeURIComponent(digest)}&kind=${kind}`),
  downloadUrl: (n: string, repo: string, digest: string, what: "cyclonedx" | "spdx" | "oval-report") =>
    `/api${r(n)}/scans/download?repo=${encodeURIComponent(repo)}&digest=${encodeURIComponent(digest)}&what=${what}`,
  sign: (n: string, repo: string, ref: string) => req<{ digest: string }>("POST", `${r(n)}/sign`, { repo, ref }),
  signing: (n: string) => req<SigningInfo>("GET", `${r(n)}/signing`),
  createSigningKey: (n: string) => req<unknown>("POST", `${r(n)}/signing-key`),
  deleteSigningKey: (n: string) => req<void>("DELETE", `${r(n)}/signing-key`),
  addTrustKey: (n: string, label: string, publicKey: string) => req<TrustKey>("POST", `${r(n)}/trust-keys`, { label, publicKey }),
  removeTrustKey: (n: string, id: number) => req<void>("DELETE", `${r(n)}/trust-keys/${id}`),
  securityStatus: () => req<SecurityStatus>("GET", "/admin/security"),
  addContentUrl: (name: string, url: string) => req<SCAPContent>("POST", "/admin/security/content", { name, url }),
  deleteContent: (name: string) => req<void>("DELETE", `/admin/security/content/${encodeURIComponent(name)}`),
  uploadContent: async (name: string, file: File) => {
    const res = await fetch(`/api/admin/security/content/${encodeURIComponent(name)}?filename=${encodeURIComponent(file.name)}`, { method: "PUT", credentials: "same-origin", body: file });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new ApiError(data.error ?? `HTTP ${res.status}`, res.status, data.code);
    return data as SCAPContent;
  },

  // add an image
  importImage: (n: string, b: ImportBody) => req<TransferView>("POST", `${r(n)}/images/import`, b),
  fixPlan: (n: string, repo: string, ref: string) => req<FixPlan>("GET", `${r(n)}/images/fix-plan?repo=${encodeURIComponent(repo)}&ref=${encodeURIComponent(ref)}`),
  fixImage: (n: string, repo: string, ref: string) => req<TransferView>("POST", `${r(n)}/images/fix`, { repo, ref }),
  rebaseImage: (n: string, b: { repo: string; ref: string; oldBase: string; baseLayers?: number; newBase: string; tag?: string; username?: string; password?: string; skipTLS?: boolean }) =>
    req<TransferView>("POST", `${r(n)}/images/rebase`, b),
  rebaseCheck: (n: string, b: { repo: string; ref: string; oldBase: string; username?: string; password?: string; skipTLS?: boolean }) =>
    req<{ matches: boolean; baseLayers: number; imageLayers: number; common: number; history: string[] }>("POST", `${r(n)}/images/rebase-check`, b),
  transfers: (n: string) => req<TransferView[]>("GET", `${r(n)}/images/transfers`),
  /** Uploads a docker-archive; XMLHttpRequest because fetch cannot report upload progress. */
  uploadImage: (n: string, file: File, o: { repo: string; tag: string; overwrite: boolean; scan: boolean }, onProgress: (sent: number, total: number) => void) =>
    new Promise<TransferView>((resolve, reject) => {
      const startedIn = epoch;
      const x = new XMLHttpRequest();
      x.open("POST", `/api${r(n)}/images/upload?${qs({ repo: o.repo, tag: o.tag, filename: file.name, overwrite: o.overwrite ? "true" : "", scan: o.scan ? "true" : "" }).slice(1)}`);
      x.upload.onprogress = (e) => e.lengthComputable && onProgress(e.loaded, e.total);
      x.onerror = () => reject(new ApiError("Network error while uploading", 0));
      x.onload = () => {
        let data: { error?: string; code?: string } = {};
        try { data = JSON.parse(x.responseText); } catch { /* not JSON */ }
        if (x.status >= 200 && x.status < 300) return resolve(data as unknown as TransferView);
        if (x.status === 401 && data.code === "unauthenticated" && startedIn === epoch) onUnauthorized?.();
        reject(new ApiError(data.error ?? (x.status === 413 ? "The file is larger than the allowed image size" : `HTTP ${x.status}`), x.status, data.code));
      };
      x.send(file);
    }),

  // administration
  accounts: () => req<Account[]>("GET", "/admin/accounts"),
  createAccount: (b: { username: string; displayName?: string; password: string; role: Role; allRegistries: boolean; registries: string[]; mustChangePassword: boolean }) =>
    req<Account>("POST", "/admin/accounts", b),
  updateAccount: (id: number, b: Partial<{ displayName: string; role: Role; disabled: boolean; allRegistries: boolean; registries: string[] }>) =>
    req<Account>("PATCH", `/admin/accounts/${id}`, b),
  deleteAccount: (id: number) => req<void>("DELETE", `/admin/accounts/${id}`),
  resetPassword: (id: number, password: string, mustChangePassword: boolean) =>
    req<unknown>("POST", `/admin/accounts/${id}/password`, { password, mustChangePassword }),
  audit: (q: AuditQuery) => req<{ entries: AuditEntry[]; next: number }>("GET", "/admin/audit" + qs({ ...q })),
  auditCsvUrl: (q: AuditQuery) => "/api/admin/audit" + qs({ ...q, before: undefined, limit: undefined, format: "csv" }),
};
