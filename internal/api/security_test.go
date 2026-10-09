package api

import (
	"bytes"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rdeb/local-image-registry/internal/auth"
	"github.com/rdeb/local-image-registry/internal/runtime"
	"github.com/rdeb/local-image-registry/internal/runtime/fake"
	"github.com/rdeb/local-image-registry/internal/service"
	"github.com/rdeb/local-image-registry/internal/store"
	"github.com/rdeb/local-image-registry/internal/vault"
)

// secEnv is newEnv with scanning enabled and a scripted tool runner.
func secEnv(t *testing.T) (*env, *fake.Driver) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	drv := fake.New()
	drv.Tool = func(runtime.ToolSpec) (runtime.ToolResult, error) {
		return runtime.ToolResult{}, runtime.ErrUnsupported
	}
	svc := service.New(st, drv, 5100, 5199)
	svc.SetReadyTimeout(0)
	v, _ := vault.New(bytes.Repeat([]byte{5}, 32))
	if err := svc.EnableSecurity(service.SecurityConfig{Vault: v, DataDir: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(svc.Close)
	a := auth.NewService(st)
	e := &env{t: t, st: st, auth: a}
	e.srv = newServer(t, svc, Options{Auth: a, Store: st})
	return e, drv
}

func TestSecurityEndpointsAreRoleAndScopeChecked(t *testing.T) {
	e, _ := secEnv(t)
	e.account("root", auth.Admin)
	e.account("op", auth.Operator, "acme")
	e.account("view", auth.Viewer, "acme")
	e.account("other", auth.Operator, "globex")
	root, op, view, other := e.as("root"), e.as("op"), e.as("view"), e.as("other")
	for _, n := range []string{"acme", "globex"} {
		if code, _, _ := root.do("POST", "/api/registries", map[string]string{"name": n, "customer": n}); code != 201 {
			t.Fatalf("create %s: %d", n, code)
		}
	}
	scan := map[string]any{"repo": "team/go", "ref": "sha256:" + strings.Repeat("a", 64), "kinds": []string{"vuln"}}

	type call struct {
		who  *client
		meth string
		path string
		body any
		want int
		why  string
	}
	for _, c := range []call{
		// reading results: any role in scope
		{view, "GET", "/api/registries/acme/scans?repo=team/go", nil, 200, "viewer reads scan list"},
		{view, "GET", "/api/registries/acme/signing", nil, 200, "viewer reads trusted keys"},
		// running things: operator and up
		{view, "POST", "/api/registries/acme/scans", scan, 403, "viewer cannot start scans"},
		{view, "POST", "/api/registries/acme/sign", map[string]string{"repo": "team/go", "ref": "v1"}, 403, "viewer cannot sign"},
		{view, "POST", "/api/registries/acme/trust-keys", map[string]string{"label": "x", "publicKey": "y"}, 403, "viewer cannot add trusted keys"},
		{op, "POST", "/api/registries/acme/trust-keys", map[string]string{"label": "x", "publicKey": "junk"}, 400, "operator may add keys (junk rejected, not forbidden)"},
		// keys: admin only
		{op, "POST", "/api/registries/acme/signing-key", nil, 403, "operator cannot create the signing key"},
		{op, "DELETE", "/api/registries/acme/signing-key", nil, 403, "operator cannot delete the signing key"},
		{root, "POST", "/api/registries/acme/signing-key", nil, 201, "admin creates the signing key"},
		{root, "POST", "/api/registries/acme/signing-key", nil, 409, "second key refused"},
		// scope: another registry looks nonexistent
		{other, "GET", "/api/registries/acme/scans?repo=team/go", nil, 404, "out-of-scope read"},
		{other, "POST", "/api/registries/acme/scans", scan, 404, "out-of-scope scan"},
		{other, "GET", "/api/registries/acme/signing", nil, 404, "out-of-scope keys"},
		{view, "GET", "/api/registries/globex/scans?repo=team/go", nil, 404, "viewer outside scope"},
		// admin-only content library and status
		{op, "GET", "/api/admin/security", nil, 403, "operator cannot see tool status"},
		{op, "POST", "/api/admin/security/content", map[string]string{"name": "x", "url": "https://example.com/a.oval.xml"}, 403, "operator cannot import content"},
		{op, "PUT", "/api/admin/security/content/rhel-9?filename=a.oval.xml", nil, 403, "operator cannot upload content"},
		{op, "DELETE", "/api/admin/security/content/rhel-9", nil, 403, "operator cannot delete content"},
		{root, "GET", "/api/admin/security", nil, 200, "admin sees status"},
		{root, "POST", "/api/admin/security/content", map[string]string{"name": "x", "url": "http://insecure.example/a.oval.xml"}, 400, "http content refused"},
		// input hardening
		{root, "GET", "/api/registries/acme/scans/result?repo=team/go&digest=../../etc/passwd&kind=vuln", nil, 400, "bad digest"},
		{root, "GET", "/api/registries/acme/scans/download?repo=team/go&digest=sha256:" + strings.Repeat("a", 64) + "&what=../x", nil, 400, "bad download kind"},
		{root, "DELETE", "/api/registries/acme/trust-keys/notanumber", nil, 404, "bad key id"},
	} {
		if code, _, raw := c.who.do(c.meth, c.path, c.body); code != c.want {
			t.Errorf("%s: %s %s -> %d, want %d (%.100s)", c.why, c.meth, c.path, code, c.want, raw)
		}
	}
	// the operator's Sign request now passes authorization and reaches the service (tool unavailable here)
	if code, _, _ := op.do("POST", "/api/registries/acme/sign", map[string]string{"repo": "team/go", "ref": "sha256:" + strings.Repeat("a", 64)}); code == 403 || code == 404 {
		t.Errorf("operator sign blocked: %d", code)
	}

	// everything above that mutates is in the audit log, including the refused attempts
	_, _, raw := root.do("GET", "/api/admin/audit?limit=200", nil)
	for _, want := range []string{`"registry.signingkey.create"`, `"registry.scan.run"`, `"registry.sign"`, `"security.content.add"`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("audit lacks %s", want)
		}
	}
	if strings.Contains(string(raw), "BEGIN") {
		t.Error("key material in the audit log")
	}
}

func TestSecurityDisabledAnswers501(t *testing.T) {
	e := newEnv(t, nil) // security not enabled
	e.account("root", auth.Admin)
	root := e.as("root")
	root.do("POST", "/api/registries", map[string]string{"name": "acme", "customer": "A"})
	if _, m, _ := e.client().do("GET", "/api/auth/config", nil); m["security"] != false {
		t.Fatalf("config must say security is off: %v", m)
	}
	for _, c := range [][2]string{{"POST", "/api/registries/acme/signing-key"}, {"GET", "/api/registries/acme/signing"}} {
		if code, _, _ := root.do(c[0], c[1], nil); code != http.StatusNotImplemented {
			t.Errorf("%v: %d", c, code)
		}
	}
	if code, _, _ := root.do("POST", "/api/registries/acme/scans", map[string]any{"repo": "a/b", "ref": "v1", "kinds": []string{"vuln"}}); code != http.StatusNotImplemented {
		t.Errorf("scan: %d", code)
	}
}
