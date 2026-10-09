package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rdeb/local-image-registry/internal/imgfs"
	"github.com/rdeb/local-image-registry/internal/runtime"
	"github.com/rdeb/local-image-registry/internal/runtime/fake"
	"github.com/rdeb/local-image-registry/internal/scanparse"
	"github.com/rdeb/local-image-registry/internal/store"
	"github.com/rdeb/local-image-registry/internal/vault"
)

const (
	dGo   = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	dOld  = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	dSigI = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" // signature index of dGo
)

// fakeReg is just enough of a registry for tag listing, digest lookup and manifest deletion.
type fakeReg struct {
	mu      sync.Mutex
	repos   map[string]map[string]string // repo -> tag -> digest
	deleted []string
	srv     *httptest.Server
}

func newFakeReg(t *testing.T) *fakeReg {
	r := &fakeReg{repos: map[string]map[string]string{"team/go": {"v1": dGo, sigTag(dGo): dSigI}, "old/app": {"3.10": dOld}}}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		defer r.mu.Unlock()
		p := strings.TrimPrefix(req.URL.Path, "/v2/")
		switch {
		case p == "_catalog":
			var names []string
			for n := range r.repos {
				names = append(names, n)
			}
			w.Write(mustJSON(map[string]any{"repositories": names}))
		case strings.Contains(p, "/tags/list"):
			repo := strings.TrimSuffix(strings.Split(p, "/tags/list")[0], "")
			tags := []string{}
			for t := range r.repos[repo] {
				tags = append(tags, t)
			}
			w.Write(mustJSON(map[string]any{"name": repo, "tags": tags}))
		case strings.Contains(p, "/manifests/"):
			repo, ref, _ := strings.Cut(p, "/manifests/")
			if req.Method == http.MethodDelete {
				r.deleted = append(r.deleted, ref)
				for tag, d := range r.repos[repo] { // like Distribution: the tags go, the empty repository name stays
					if d == ref {
						delete(r.repos[repo], tag)
					}
				}
				w.WriteHeader(http.StatusAccepted)
				return
			}
			d, ok := r.repos[repo][ref]
			if strings.HasPrefix(ref, "sha256:") {
				d, ok = ref, true
			}
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Docker-Content-Digest", d)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(r.srv.Close)
	return r
}

type rig struct {
	svc  *Service
	drv  *fake.Driver
	reg  *fakeReg
	st   *store.Store
	dir  string
	mu   sync.Mutex
	runs []runtime.ToolSpec
}

func newRig(t *testing.T, tool func(runtime.ToolSpec) (runtime.ToolResult, error)) *rig {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	drv := fake.New()
	svc := New(st, drv, 5100, 5199)
	svc.SetReadyTimeout(0)
	reg := newFakeReg(t)
	if _, err := svc.Create(context.Background(), CreateInput{Name: "acme", Customer: "Acme"}); err != nil {
		t.Fatal(err)
	}
	drv.Endpoints = map[string]string{"acme": strings.TrimPrefix(reg.srv.URL, "http://")}
	v, _ := vault.New(bytes.Repeat([]byte{3}, 32))
	r := &rig{svc: svc, drv: drv, reg: reg, st: st, dir: t.TempDir()}
	drv.Tool = func(sp runtime.ToolSpec) (runtime.ToolResult, error) {
		r.mu.Lock()
		r.runs = append(r.runs, sp)
		r.mu.Unlock()
		if tool == nil {
			return runtime.ToolResult{}, runtime.ErrUnsupported
		}
		return tool(sp)
	}
	if err := svc.EnableSecurity(SecurityConfig{Vault: v, DataDir: r.dir, Workers: 2}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(svc.Close)
	return r
}

func (r *rig) wait(t *testing.T, repo, digest, kind string) ScanView {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		views, _ := r.svc.ScanStatuses("acme", repo)
		for _, v := range views {
			if v.Digest == digest && v.Kind == kind && (v.Status == store.ScanDone || v.Status == store.ScanFailed) {
				return v
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("scan %s/%s never finished", kind, digest)
	return ScanView{}
}

func (r *rig) scan(t *testing.T, repo, ref string, kinds ...string) string {
	t.Helper()
	d, _, err := r.svc.StartScans(context.Background(), "acme", repo, ref, kinds, "tester")
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func (r *rig) toolRuns() []runtime.ToolSpec {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]runtime.ToolSpec(nil), r.runs...)
}

func ok(out string) (runtime.ToolResult, error) { return runtime.ToolResult{Stdout: []byte(out)}, nil }

const grypeJSON = `{"matches":[{"vulnerability":{"id":"CVE-1","severity":"Critical","fix":{"versions":["2"],"state":"fixed"}},"artifact":{"name":"openssl","version":"1","type":"apk"}},
{"vulnerability":{"id":"CVE-2","severity":"High","fix":{}},"artifact":{"name":"zlib","version":"1","type":"apk"}}],"descriptor":{"version":"0.119.0","db":{"status":{"built":"2026-10-08T00:00:00Z"}}}}`
const cdxJSON = `{"bomFormat":"CycloneDX","specVersion":"1.7","components":[{"name":"zlib","version":"1","purl":"pkg:apk/alpine/zlib@1"},{"name":"f","type":"file"}]}`

func hasArg(sp runtime.ToolSpec, a string) bool {
	for _, x := range sp.Args {
		if x == a {
			return true
		}
	}
	return false
}

func TestVulnScanRunsGrypeSafelyAndStoresResult(t *testing.T) {
	r := newRig(t, func(sp runtime.ToolSpec) (runtime.ToolResult, error) { return ok(grypeJSON) })
	d := r.scan(t, "team/go", "v1", KindVuln)
	if d != dGo {
		t.Fatalf("tag must resolve to its digest: %s", d)
	}
	v := r.wait(t, "team/go", d, KindVuln)
	if v.Status != store.ScanDone || !strings.Contains(string(v.Summary), `"critical":1`) || !strings.Contains(v.Tool, "grype 0.119.0") {
		t.Fatalf("%+v", v)
	}

	runs := r.toolRuns()
	if len(runs) != 1 {
		t.Fatalf("runs: %d", len(runs))
	}
	sp := runs[0]
	if sp.Image != DefaultToolImages().Grype || !sp.HostNetwork || len(sp.Volumes) != 1 || sp.Volumes[0].Dest != "/db" {
		t.Fatalf("spec %+v", sp)
	}
	rec, _ := r.st.Get("acme")
	for _, a := range sp.Args {
		if strings.Contains(a, rec.AdminPass) {
			t.Fatal("registry password leaked into the tool's arguments")
		}
	}
	if sp.Env["GRYPE_REGISTRY_AUTH_PASSWORD"] != rec.AdminPass || sp.Env["GRYPE_REGISTRY_AUTH_USERNAME"] != "_admin" || sp.Env["GRYPE_REGISTRY_INSECURE_USE_HTTP"] != "true" {
		t.Fatalf("env %v", sp.Env)
	}
	if !hasArg(sp, "registry:"+strings.TrimPrefix(r.reg.srv.URL, "http://")+"/team/go@"+dGo) {
		t.Fatalf("scans by digest, not by mutable tag: %v", sp.Args)
	}

	det, err := r.svc.ScanDetail("acme", "team/go", d, KindVuln)
	if err != nil || !strings.Contains(string(det.(json.RawMessage)), "CVE-1") {
		t.Fatalf("detail: %v %v", det, err)
	}

	sum, _, _ := r.svc.Fleet(context.Background(), func(string) bool { return true })
	if sum.CriticalVulns != 1 || sum.HighVulns != 1 || sum.ScannedImages != 1 || sum.RegistriesWithCritical != 1 {
		t.Fatalf("fleet totals %+v", sum)
	}
}

func TestScanFailureIsReportedWithoutSecrets(t *testing.T) {
	var pass string
	r := newRig(t, func(sp runtime.ToolSpec) (runtime.ToolResult, error) {
		pass = sp.Env["GRYPE_REGISTRY_AUTH_PASSWORD"]
		return runtime.ToolResult{ExitCode: 1, Stderr: []byte("failed to fetch: password " + pass + " rejected")}, nil
	})
	d := r.scan(t, "team/go", "v1", KindVuln)
	v := r.wait(t, "team/go", d, KindVuln)
	if v.Status != store.ScanFailed || !strings.Contains(v.Error, "grype failed") || strings.Contains(v.Error, pass) {
		t.Fatalf("%+v", v)
	}
	// a driver without tool support (e.g. Kubernetes limits) fails cleanly too
	r2 := newRig(t, nil)
	d = r2.scan(t, "team/go", "v1", KindVuln)
	if v := r2.wait(t, "team/go", d, KindVuln); v.Status != store.ScanFailed {
		t.Fatalf("%+v", v)
	}
}

func TestRescanAndDuplicateSuppression(t *testing.T) {
	release := make(chan struct{})
	r := newRig(t, func(sp runtime.ToolSpec) (runtime.ToolResult, error) { <-release; return ok(grypeJSON) })
	ctx := context.Background()
	_, q1, _ := r.svc.StartScans(ctx, "acme", "team/go", "v1", []string{KindVuln}, "a")
	_, q2, _ := r.svc.StartScans(ctx, "acme", "team/go", "v1", []string{KindVuln}, "b")
	if len(q1) != 1 || len(q2) != 0 {
		t.Fatalf("a second click while running must not queue a second scan: %v %v", q1, q2)
	}
	close(release)
	r.wait(t, "team/go", dGo, KindVuln)
	if _, q, _ := r.svc.StartScans(ctx, "acme", "team/go", "v1", []string{KindVuln}, "c"); len(q) != 1 {
		t.Fatal("rescan after completion must be allowed")
	}
}

func TestInputValidation(t *testing.T) {
	r := newRig(t, nil)
	ctx := context.Background()
	for _, c := range []struct {
		repo, ref string
		kinds     []string
	}{
		{"team/go", "v1", nil},
		{"team/go", "v1", []string{"rm -rf"}},
		{"../etc", "v1", []string{KindVuln}},
		{"team/go", "bad/tag", []string{KindVuln}},
	} {
		if _, _, err := r.svc.StartScans(ctx, "acme", c.repo, c.ref, c.kinds, "x"); err == nil {
			t.Errorf("%+v accepted", c)
		}
	}
	for _, repo := range []string{"team/go@sha256:" + strings.Repeat("a", 64), "UPPER", "a b", "x;rm -rf", ""} {
		if _, _, err := r.svc.StartScans(ctx, "acme", repo, dGo, []string{KindVuln}, "x"); !errors.Is(err, ErrInvalid) {
			t.Errorf("repo %q with a digest ref bypassed validation: %v", repo, err)
		}
		if _, err := r.svc.Sign(ctx, "acme", repo, dGo, "x"); err == nil {
			t.Errorf("sign accepted repo %q", repo)
		}
	}
	if _, _, err := r.svc.StartScans(ctx, "nope", "team/go", "v1", []string{KindVuln}, "x"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown registry: %v", err)
	}
	for _, d := range []string{"", "sha256:short", "sha256:" + strings.Repeat("Z", 64)} {
		if _, err := r.svc.ScanDetail("acme", "team/go", d, KindVuln); err == nil {
			t.Errorf("digest %q accepted", d)
		}
	}
	if _, _, _, err := r.svc.Download("acme", "team/go", dGo, "../../etc/passwd"); err == nil {
		t.Error("arbitrary download name accepted")
	}
	// security off
	st2, _ := store.Open(filepath.Join(t.TempDir(), "x.db"))
	defer st2.Close()
	plain := New(st2, fake.New(), 5100, 5199)
	if _, _, err := plain.StartScans(ctx, "acme", "r", "t", []string{KindVuln}, "x"); !errors.Is(err, ErrSecurityDisabled) {
		t.Errorf("disabled: %v", err)
	}
}

func TestSBOMStoresBothFormats(t *testing.T) {
	r := newRig(t, func(sp runtime.ToolSpec) (runtime.ToolResult, error) {
		if hasArg(sp, "spdx-json") {
			return ok(`{"spdxVersion":"SPDX-2.3","packages":[]}`)
		}
		return ok(cdxJSON)
	})
	d := r.scan(t, "team/go", "v1", KindSBOM)
	if v := r.wait(t, "team/go", d, KindSBOM); v.Status != store.ScanDone || !strings.Contains(string(v.Summary), `"packages":1`) || !strings.Contains(string(v.Summary), `"files":1`) {
		t.Fatalf("%+v", v)
	}
	for what, want := range map[string]string{"cyclonedx": "CycloneDX", "spdx": "SPDX-2.3"} {
		data, name, ct, err := r.svc.Download("acme", "team/go", d, what)
		if err != nil || !strings.Contains(string(data), want) || ct != "application/json" || !strings.HasSuffix(name, what+".json") || strings.ContainsAny(name, "/:") {
			t.Fatalf("%s: %q %q %q %v", what, data, name, ct, err)
		}
	}
	det, err := r.svc.ScanDetail("acme", "team/go", d, KindSBOM)
	if err != nil || det.(scanparse.SBOMReport).Summary.Packages != 1 {
		t.Fatalf("%v %v", det, err)
	}
}

func sigOf(t *testing.T, r *rig, repo, digest string) (string, string) {
	t.Helper()
	v := r.wait(t, repo, digest, KindSig)
	if v.Status != store.ScanDone {
		t.Fatalf("sig scan failed: %s", v.Error)
	}
	var s struct{ Status, Key string }
	if err := json.Unmarshal(v.Summary, &s); err != nil {
		t.Fatal(err)
	}
	return s.Status, s.Key
}

func TestSignatureStatuses(t *testing.T) {
	var mode string
	r := newRig(t, func(sp runtime.ToolSpec) (runtime.ToolResult, error) {
		switch mode {
		case "signed":
			return ok("verified")
		case "unsigned":
			return runtime.ToolResult{ExitCode: 1, Stderr: []byte("Error: no signatures found")}, nil
		case "wrongkey":
			return runtime.ToolResult{ExitCode: 1, Stderr: []byte("accepted signatures do not match threshold, Found: 0, Expected 1")}, nil
		}
		return runtime.ToolResult{ExitCode: 1, Stderr: []byte("UNAUTHORIZED: authentication required")}, nil
	})
	// no trusted keys: only the presence of a signature can be reported
	if st, _ := sigOf(t, r, "team/go", r.scan(t, "team/go", "v1", KindSig)); st != "unverified" {
		t.Fatalf("signed image, no keys: %s", st)
	}
	if st, _ := sigOf(t, r, "old/app", r.scan(t, "old/app", "3.10", KindSig)); st != "unsigned" {
		t.Fatalf("unsigned image, no keys: %s", st)
	}
	if len(r.toolRuns()) != 0 {
		t.Fatal("cosign must not run without keys")
	}

	pub := "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEh2xkWp6kKSriYATqlR5fFcKxAT2N\nybaUuN0VNKgoEm/9lmmWUEqilN+fLOTd/9KkP0gNggI+WyBKQnTVoBApFw==\n-----END PUBLIC KEY-----\n"
	if _, err := r.svc.AddTrustKey("acme", "Release key", pub); err != nil {
		t.Fatal(err)
	}
	if _, err := r.svc.AddTrustKey("acme", "dup", pub); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate key: %v", err)
	}
	for _, c := range []struct{ mode, want string }{{"signed", "signed"}, {"unsigned", "unsigned"}, {"wrongkey", "invalid"}} {
		mode = c.mode
		st, key := sigOf(t, r, "team/go", r.scan(t, "team/go", "v1", KindSig))
		if st != c.want || (c.want == "signed" && key != "Release key") {
			t.Fatalf("%s: got %s/%s", c.mode, st, key)
		}
	}
	last := r.toolRuns()[len(r.toolRuns())-1]
	if last.Env["COSIGN_PUB"] != pub || !hasArg(last, "--allow-http-registry") || !hasArg(last, "--insecure-ignore-tlog") {
		t.Fatalf("verify spec %+v", last)
	}
	for _, a := range last.Args {
		if strings.Contains(a, "BEGIN") {
			t.Fatal("public key passed in argv")
		}
	}
	// an unclassifiable failure (bad credentials, network) is a failed scan, not a verdict
	mode = "auth"
	if v := r.wait(t, "team/go", r.scan(t, "team/go", "v1", KindSig), KindSig); v.Status != store.ScanFailed {
		t.Fatalf("auth failure must fail the scan: %+v", v)
	}
	if _, err := r.svc.AddTrustKey("acme", "bad", "not a key"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("junk key: %v", err)
	}
	if _, err := r.svc.AddTrustKey("acme", "x<script>", pub); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad label: %v", err)
	}
}

func TestSigningKeyLifecycleAndSign(t *testing.T) {
	r := newRig(t, func(sp runtime.ToolSpec) (runtime.ToolResult, error) { return ok("ok") })
	ctx := context.Background()
	if _, err := r.svc.Sign(ctx, "acme", "team/go", "v1", "u"); !errors.Is(err, ErrNoSigningKey) {
		t.Fatalf("sign without a key: %v", err)
	}
	ki, err := r.svc.CreateSigningKey("acme")
	if err != nil || !strings.Contains(ki.PublicKey, "PUBLIC KEY") || !strings.HasPrefix(ki.Fingerprint, "SHA256:") {
		t.Fatalf("%+v %v", ki, err)
	}
	if _, err := r.svc.CreateSigningKey("acme"); !errors.Is(err, ErrExists) {
		t.Fatalf("second key: %v", err)
	}
	sk, _ := r.st.GetSigningKey("acme")
	if bytes.Contains(sk.PrivateEnc, []byte("SIGSTORE")) || bytes.Contains(sk.PrivateEnc, []byte("PRIVATE")) {
		t.Fatal("private key stored in clear")
	}
	info, _ := r.svc.SigningInfo("acme")
	if info.SigningKey == nil || len(info.TrustedKeys) != 1 || !info.TrustedKeys[0].Own {
		t.Fatalf("%+v", info)
	}

	d, err := r.svc.Sign(ctx, "acme", "team/go", "v1", "u")
	if err != nil || d != dGo {
		t.Fatalf("%q %v", d, err)
	}
	var sign runtime.ToolSpec
	for _, sp := range r.toolRuns() {
		if hasArg(sp, "sign") {
			sign = sp
		}
	}
	if !strings.Contains(sign.Env["SIGN_KEY"], "ENCRYPTED SIGSTORE PRIVATE KEY") || sign.Env["COSIGN_PASSWORD"] == "" {
		t.Fatalf("signer env %v", sign.Env)
	}
	for _, a := range sign.Args {
		if strings.Contains(a, sign.Env["COSIGN_PASSWORD"]) || strings.Contains(a, "BEGIN") {
			t.Fatal("key material in argv")
		}
	}
	if !hasArg(sign, "--tlog-upload=false") || !hasArg(sign, "--use-signing-config=false") {
		t.Fatalf("offline signing flags missing: %v", sign.Args)
	}
	r.wait(t, "team/go", dGo, KindSig) // the follow-up verification was queued

	if err := r.svc.DeleteSigningKey("acme"); err != nil {
		t.Fatal(err)
	}
	info, _ = r.svc.SigningInfo("acme")
	if info.SigningKey != nil || len(info.TrustedKeys) != 1 {
		t.Fatalf("deleting the private key must keep the public key trusted: %+v", info)
	}
	// a failing signer must not leak the passphrase in its error
	r.drv.Tool = func(sp runtime.ToolSpec) (runtime.ToolResult, error) {
		return runtime.ToolResult{ExitCode: 1, Stderr: []byte("bad pass " + sp.Env["COSIGN_PASSWORD"])}, nil
	}
	_, _ = r.svc.CreateSigningKey("acme")
	if _, err := r.svc.Sign(ctx, "acme", "team/go", "v1", "u"); err == nil || strings.Contains(err.Error(), "bad pass ") && !strings.Contains(err.Error(), "***") {
		t.Fatalf("passphrase leaked or no error: %v", err)
	}
}

const ovalXML = `<?xml version="1.0"?><oval_results><oval_definitions><definitions>
<definition id="d1" class="patch"><metadata><title>RHSA-1: openssl</title><reference source="RHSA" ref_id="RHSA-2026:1" ref_url="https://access.redhat.com/errata/RHSA-2026:1"/><advisory><severity>Important</severity><cve>CVE-9</cve></advisory></metadata></definition>
</definitions></oval_definitions><results><system><definitions><definition definition_id="d1" result="true"/></definitions></system></results></oval_results>`

func TestOVALScanApplicabilityAndRun(t *testing.T) {
	osRelease := "ID=alpine\nVERSION_ID=3.10.9\nPRETTY_NAME=\"Alpine Linux v3.10\"\n"
	r := newRig(t, func(sp runtime.ToolSpec) (runtime.ToolResult, error) {
		var out string
		for _, m := range sp.Mounts {
			if m.Dest == "/out" {
				out = m.Host
			}
		}
		if err := os.WriteFile(filepath.Join(out, "results.xml"), []byte(ovalXML), 0o600); err != nil {
			t.Error(err)
		}
		os.WriteFile(filepath.Join(out, "report.html"), []byte("<html>report</html>"), 0o600)
		return ok("done")
	})
	r.svc.sec.pull = func(ctx context.Context, src imgfs.Source, dest string) error {
		if err := os.MkdirAll(filepath.Join(dest, "etc"), 0o700); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dest, "etc/os-release"), []byte(osRelease), 0o600)
	}

	// 1. Alpine: not applicable, and the tool must not even run
	d := r.scan(t, "old/app", "3.10", KindOVAL)
	v := r.wait(t, "old/app", d, KindOVAL)
	if v.Status != store.ScanDone || !strings.Contains(string(v.Summary), `"applicable":false`) || !strings.Contains(string(v.Summary), "Alpine") {
		t.Fatalf("%+v", v)
	}
	if len(r.toolRuns()) != 0 {
		t.Fatal("oscap ran on a non-RHEL image")
	}

	// 2. RHEL without library content: actionable failure
	osRelease = "ID=\"rhel\"\nVERSION_ID=\"9.2\"\nPRETTY_NAME=\"Red Hat Enterprise Linux 9.2\"\n"
	d = r.scan(t, "team/go", "v1", KindOVAL)
	if v := r.wait(t, "team/go", d, KindOVAL); v.Status != store.ScanFailed || !strings.Contains(v.Error, "rhel-9") {
		t.Fatalf("%+v", v)
	}

	// 3. with content: runs oscap with the right isolation and parses the result
	if _, err := r.svc.AddContentUpload("rhel-9", "rhel-9.oval.xml", strings.NewReader("<?xml version=\"1.0\"?><oval_definitions/>"), "test", "admin"); err != nil {
		t.Fatal(err)
	}
	d = r.scan(t, "team/go", "v1", KindOVAL)
	v = r.wait(t, "team/go", d, KindOVAL)
	if v.Status != store.ScanDone || !strings.Contains(string(v.Summary), `"vulnerable":1`) || !strings.Contains(string(v.Summary), `"important":1`) || !strings.Contains(string(v.Summary), "Red Hat Enterprise Linux 9.2") {
		t.Fatalf("%+v", v)
	}
	sp := r.toolRuns()[0]
	if !sp.Root || len(sp.Caps) != 1 || sp.Caps[0] != "SYS_CHROOT" || sp.Env["OSCAP_PROBE_ROOT"] != "/target" {
		t.Fatalf("oscap isolation %+v", sp)
	}
	var target, content *runtime.ToolMount
	for i := range sp.Mounts {
		switch sp.Mounts[i].Dest {
		case "/target":
			target = &sp.Mounts[i]
		case "/content":
			content = &sp.Mounts[i]
		}
	}
	if target == nil || !target.ReadOnly || content == nil || !content.ReadOnly {
		t.Fatalf("image and content must be mounted read-only: %+v", sp.Mounts)
	}
	html, name, ct, err := r.svc.Download("acme", "team/go", d, "oval-report")
	if err != nil || string(html) != "<html>report</html>" || !strings.HasPrefix(ct, "text/html") || !strings.HasSuffix(name, ".html") {
		t.Fatalf("report: %q %q %q %v", html, name, ct, err)
	}
	if entries, _ := os.ReadDir(filepath.Join(r.dir, "scratch")); len(entries) != 0 {
		t.Fatalf("unpacked image left behind: %v", entries)
	}
}

func TestOSReleaseIsConfinedToTheImage(t *testing.T) {
	base := t.TempDir()
	os.WriteFile(filepath.Join(base, "host-os-release"), []byte("ID=rhel\nVERSION_ID=9\n"), 0o600)
	root := filepath.Join(base, "root")
	os.MkdirAll(filepath.Join(root, "etc"), 0o700)
	// an image whose os-release is an absolute symlink to a *host* file
	os.Symlink(filepath.Join(base, "host-os-release"), filepath.Join(root, "etc/os-release"))
	if _, id, _ := readOSRelease(root); id != "" {
		t.Fatalf("followed a symlink out of the image: %q", id)
	}
	os.Remove(filepath.Join(root, "etc/os-release"))
	os.MkdirAll(filepath.Join(root, "usr/lib"), 0o700)
	os.WriteFile(filepath.Join(root, "usr/lib/os-release"), []byte("ID=rhel\nVERSION_ID=\"8.9\"\nPRETTY_NAME=\"RHEL 8.9\"\n"), 0o600)
	os.Symlink("../usr/lib/os-release", filepath.Join(root, "etc/os-release"))
	if pretty, id, major := readOSRelease(root); id != "rhel" || major != "8" || pretty != "RHEL 8.9" {
		t.Fatalf("%q %q %q", pretty, id, major)
	}
}

func TestContentLibraryValidation(t *testing.T) {
	r := newRig(t, nil)
	good := "<?xml version=\"1.0\"?><oval_definitions/>"
	for _, c := range []struct{ name, file, body string }{
		{"Bad Name", "a.oval.xml", good},
		{"../x", "a.oval.xml", good},
		{"ok", "../a.oval.xml", good},
		{"ok", "a.exe", good},
		{"ok", "a.oval.xml", "MZ\x90\x00 not xml"},
		{"ok", "a.oval.xml", ""},
	} {
		if _, err := r.svc.AddContentUpload(c.name, c.file, strings.NewReader(c.body), "t", "a"); !errors.Is(err, ErrInvalid) {
			t.Errorf("%+v accepted: %v", c, err)
		}
	}
	c, err := r.svc.AddContentUpload("rhel-9", "rhel-9.oval.xml.bz2", strings.NewReader("BZh91AY&SY..."), "upload", "admin")
	if err != nil || c.Size == 0 || len(c.SHA256) != 64 {
		t.Fatalf("%+v %v", c, err)
	}
	if _, err := r.svc.AddContentUpload("rhel-9", "rhel-9.oval.xml", strings.NewReader(good), "upload", "admin"); err != nil {
		t.Fatalf("replace: %v", err)
	}
	if l, _ := r.svc.ContentList(); len(l) != 1 || l[0].Filename != "rhel-9.oval.xml" {
		t.Fatalf("%+v", l)
	}
	entries, _ := os.ReadDir(filepath.Join(r.dir, "scap", "rhel-9"))
	if len(entries) != 1 {
		t.Fatalf("old file left behind: %v", entries)
	}
	if err := r.svc.DeleteContent("rhel-9"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(r.dir, "scap", "rhel-9")); err == nil {
		t.Fatal("content directory not removed")
	}

	ctx := context.Background()
	for _, u := range []string{"http://example.com/a.oval.xml", "ftp://x/a.xml", "https://127.0.0.1:1/a.oval.xml", "https://169.254.169.254/latest/a.oval.xml", "https://localhost/a.oval.xml", "https://example.com/", "https://example.com/a.exe"} {
		if _, err := r.svc.AddContentURL(ctx, "x", u, "a"); err == nil {
			t.Errorf("%s accepted", u)
		}
	}
}

func TestTagsMarkSignaturesPruneScansAndDeleteCleansUp(t *testing.T) {
	r := newRig(t, func(sp runtime.ToolSpec) (runtime.ToolResult, error) { return ok(grypeJSON) })
	ctx := context.Background()
	dg := r.scan(t, "team/go", "v1", KindVuln)
	r.wait(t, "team/go", dg, KindVuln)
	// stale result for an image that no longer exists in the registry
	r.st.QueueScan("acme", "team/go", dOld, KindVuln, "x")
	r.st.FinishScan(store.Scan{Registry: "acme", Repo: "team/go", Digest: dOld, Kind: KindVuln, Status: store.ScanDone})

	tags, err := r.svc.Tags(ctx, "acme", "team/go")
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]string{}
	for _, tg := range tags {
		kinds[tg.Tag] = tg.Kind
	}
	if kinds["v1"] != "image" || kinds[sigTag(dGo)] != "signature" {
		t.Fatalf("kinds %v", kinds)
	}
	views, _ := r.svc.ScanStatuses("acme", "team/go")
	if len(views) != 1 || views[0].Digest != dGo {
		t.Fatalf("scan of a vanished image not pruned: %+v", views)
	}

	if _, err := r.svc.DeleteTag(ctx, "acme", "team/go", "v1"); err != nil {
		t.Fatal(err)
	}
	r.reg.mu.Lock()
	deleted := strings.Join(r.reg.deleted, ",")
	r.reg.mu.Unlock()
	if !strings.Contains(deleted, dGo) || !strings.Contains(deleted, dSigI) {
		t.Fatalf("image and its signature must both be deleted: %s", deleted)
	}
	if views, _ := r.svc.ScanStatuses("acme", "team/go"); len(views) != 0 {
		t.Fatalf("scan results of a deleted image kept: %+v", views)
	}
}

func TestInterruptedScansAreMarkedFailedAtStartup(t *testing.T) {
	r := newRig(t, nil)
	r.st.QueueScan("acme", "team/go", dGo, KindVuln, "x")
	r.st.StartScan("acme", "team/go", dGo, KindVuln)
	r.st.QueueScan("acme", "team/go", dGo, KindSBOM, "x")
	if err := r.svc.EnableSecurity(SecurityConfig{Vault: r.svc.sec.cfg.Vault, DataDir: r.dir}); err == nil {
		t.Fatal("enabling twice on one service must be refused")
	}
	// A restart is a new Service on the same database.
	restarted := New(r.st, r.drv, 5100, 5199)
	if err := restarted.EnableSecurity(SecurityConfig{Vault: r.svc.sec.cfg.Vault, DataDir: r.dir}); err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	views, _ := restarted.ScanStatuses("acme", "team/go")
	if len(views) != 2 {
		t.Fatalf("%+v", views)
	}
	for _, v := range views {
		if v.Status != store.ScanFailed || !strings.Contains(v.Error, "restart") {
			t.Fatalf("%+v", v)
		}
	}
}

func TestRegistryDeletionRemovesSecurityData(t *testing.T) {
	r := newRig(t, func(sp runtime.ToolSpec) (runtime.ToolResult, error) { return ok(grypeJSON) })
	r.wait(t, "team/go", r.scan(t, "team/go", "v1", KindVuln), KindVuln)
	r.svc.CreateSigningKey("acme")
	if err := r.svc.Delete(context.Background(), "acme", true); err != nil {
		t.Fatal(err)
	}
	if l, _ := r.st.ListScans("acme", ""); len(l) != 0 {
		t.Fatalf("scans survive: %v", l)
	}
	if _, err := r.st.GetSigningKey("acme"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("signing key survives registry deletion")
	}
	if k, _ := r.st.TrustKeys("acme"); len(k) != 0 {
		t.Fatal("trust keys survive")
	}
}

func TestRepoSummariesCountImageTagsAndHideEmptyRepositories(t *testing.T) {
	r := newRig(t, nil)
	r.reg.mu.Lock()
	r.reg.repos["empty/repo"] = map[string]string{} // lingering catalog entry after its last tag was deleted
	r.reg.repos["only/sigs"] = map[string]string{sigTag(dOld): dSigI}
	r.reg.mu.Unlock()
	got, err := r.svc.RepoSummaries(context.Background(), "acme")
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, g := range got {
		counts[g.Name] = g.Tags
	}
	if len(counts) != 2 || counts["team/go"] != 1 || counts["old/app"] != 1 {
		t.Fatalf("signature tags must not count and empty repositories must be hidden: %v", counts)
	}
}

func TestDeleteRepositoryRemovesEveryImageSignatureAndScanResult(t *testing.T) {
	r := newRig(t, func(sp runtime.ToolSpec) (runtime.ToolResult, error) { return ok(grypeJSON) })
	ctx := context.Background()
	r.reg.mu.Lock()
	r.reg.repos["team/go"]["latest"] = dGo // two tags, one manifest
	r.reg.repos["team/go"]["v2"] = dOld    // a second image
	r.reg.mu.Unlock()
	r.wait(t, "team/go", r.scan(t, "team/go", "v1", KindVuln), KindVuln)

	res, err := r.svc.DeleteRepository(ctx, "acme", "team/go")
	if err != nil {
		t.Fatal(err)
	}
	if res.Tags != 3 || res.Manifests != 3 {
		t.Fatalf("3 image tags over 2 manifests plus the signature index: %+v", res)
	}
	r.reg.mu.Lock()
	deleted := strings.Join(r.reg.deleted, ",")
	left := len(r.reg.repos["team/go"])
	other := len(r.reg.repos["old/app"])
	r.reg.mu.Unlock()
	for _, d := range []string{dGo, dOld, dSigI} {
		if strings.Count(deleted, d) != 1 {
			t.Fatalf("%s must be deleted exactly once (shared manifests deduplicated): %s", d, deleted)
		}
	}
	if left != 0 || other != 1 {
		t.Fatalf("only the target repository may be emptied: team/go has %d tags, old/app %d", left, other)
	}
	if views, _ := r.svc.ScanStatuses("acme", "team/go"); len(views) != 0 {
		t.Fatalf("scan results of a deleted repository kept: %+v", views)
	}
	sums, _ := r.svc.RepoSummaries(ctx, "acme")
	for _, s := range sums {
		if s.Name == "team/go" {
			t.Fatal("deleted repository is still listed")
		}
	}
	if _, err := r.svc.DeleteRepository(ctx, "acme", "team/go"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleting it again: %v", err)
	}
	for _, bad := range []string{"../etc", "UPPER", "a b", "", "x@sha256:" + strings.Repeat("a", 64)} {
		if _, err := r.svc.DeleteRepository(ctx, "acme", bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

func TestFixPlanUsesOnlyFixableRPMPackagesAndRefusesUnsafeInput(t *testing.T) {
	r := newRig(t, nil)
	ctx := context.Background()
	put := func(digest string, rep scanparse.VulnReport) {
		t.Helper()
		sum, _ := json.Marshal(rep.Summary)
		if _, err := r.st.QueueScan("acme", "team/go", digest, KindVuln, "op"); err != nil {
			t.Fatal(err)
		}
		if err := r.st.FinishScan(store.Scan{Registry: "acme", Repo: "team/go", Digest: digest, Kind: KindVuln, Status: store.ScanDone, Summary: string(sum), Result: gz(mustJSON(rep))}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := r.svc.PlanFix(ctx, "acme", "team/go", "v1", ""); !errors.Is(err, ErrNotReady) {
		t.Fatalf("an unscanned image must ask for a scan first, got %v", err)
	}

	put(dGo, scanparse.VulnReport{Summary: scanparse.VulnSummary{Total: 3}, Vulns: []scanparse.Vuln{
		{ID: "CVE-1", Package: "openssl-libs", Type: "rpm", FixedIn: []string{"1:3.0.7-2"}},
		{ID: "CVE-2", Package: "openssl-libs", Type: "rpm", FixedIn: []string{"1:3.0.7-2"}},
		{ID: "CVE-3", Package: "--installroot=/", Type: "rpm", FixedIn: []string{"1"}}, // must never reach argv
		{ID: "CVE-4", Package: "left-pad", Type: "npm", FixedIn: []string{"2"}},        // not an OS package
		{ID: "CVE-5", Package: "zlib", Type: "rpm"},                                    // no fixed version
	}})
	plan, err := r.svc.PlanFix(ctx, "acme", "team/go", "v1", "")
	if err != nil || plan.All || len(plan.Packages) != 1 || plan.Packages[0] != "openssl-libs" || plan.NewTag != "v1-fixed" {
		t.Fatalf("plan = %+v, %v", plan, err)
	}

	put(dGo, scanparse.VulnReport{Summary: scanparse.VulnSummary{Total: 2}, Vulns: []scanparse.Vuln{{ID: "CVE-9", Package: "zlib", Type: "rpm"}}})
	if plan, err = r.svc.PlanFix(ctx, "acme", "team/go", "v1", ""); err != nil || !plan.All || len(plan.Packages) != 0 {
		t.Fatalf("with nothing individually fixable the plan is to update everything: %+v, %v", plan, err)
	}

	put(dGo, scanparse.VulnReport{})
	if _, err := r.svc.PlanFix(ctx, "acme", "team/go", "v1", ""); !errors.Is(err, ErrNothingToFix) {
		t.Fatalf("a clean image has nothing to fix, got %v", err)
	}
	put(dGo, scanparse.VulnReport{Summary: scanparse.VulnSummary{Total: 1}})
	for _, c := range []struct{ repo, ref, tag string }{
		{"team/go", "v1", "v1"},       // would overwrite the original
		{"team/go", "v1", "bad tag!"}, // invalid tag
		{"team/go", dGo, ""},          // a digest needs an explicit tag
		{"../etc", "v1", ""},          // invalid repository
	} {
		if _, err := r.svc.FixImage(ctx, "acme", c.repo, c.ref, c.tag, "op"); !errors.Is(err, ErrInvalid) {
			t.Errorf("FixImage(%+v) = %v, want ErrInvalid", c, err)
		}
	}
}

func TestFixManagerFollowsOSPackageTypes(t *testing.T) {
	v := func(types ...string) (rep scanparse.VulnReport) {
		for _, ty := range types {
			rep.Vulns = append(rep.Vulns, scanparse.Vuln{Type: ty, Package: "p", FixedIn: []string{"1"}})
		}
		return
	}
	for _, c := range []struct {
		rep  scanparse.VulnReport
		want string
	}{
		{v("rpm", "rpm", "npm"), "dnf"}, {v("apk", "apk"), "apk"}, {v("apk", "rpm", "rpm"), "dnf"},
		{v("deb", "deb", "python", "binary"), "apt"}, {v("npm", "python", "go-module"), ""}, {v(), ""},
	} {
		if got := fixManager(c.rep); got != c.want {
			t.Errorf("fixManager = %q, want %q", got, c.want)
		}
	}
	if got := fixablePackages(v("apk", "rpm"), "apk"); len(got) != 1 {
		t.Errorf("only packages of the manager's own type count: %v", got)
	}
}
