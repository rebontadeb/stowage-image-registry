package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rdeb/local-image-registry/internal/auth"
	"github.com/rdeb/local-image-registry/internal/runtime/fake"
	"github.com/rdeb/local-image-registry/internal/service"
	"github.com/rdeb/local-image-registry/internal/store"
)

const pw = "a-long-test-password"

type env struct {
	t    *testing.T
	srv  *httptest.Server
	st   *store.Store
	auth *auth.Service
}

func newEnv(t *testing.T, mod func(*Options)) *env {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	svc := service.New(st, fake.New(), 5100, 5199)
	svc.SetReadyTimeout(0)
	a := auth.NewService(st)
	opt := Options{Auth: a, Store: st}
	if mod != nil {
		mod(&opt)
	}
	return &env{t: t, srv: newServer(t, svc, opt), st: st, auth: a}
}

func newServer(t *testing.T, svc *service.Service, opt Options) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(Secure(New(svc, opt)))
	t.Cleanup(srv.Close)
	return srv
}

type client struct {
	e *env
	c *http.Client
}

func (e *env) client() *client {
	jar, _ := cookiejar.New(nil)
	return &client{e: e, c: &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func (c *client) do(method, path string, body any, hdr ...string) (int, map[string]any, []byte) {
	c.e.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, c.e.srv.URL+path, rd)
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := c.c.Do(req)
	if err != nil {
		c.e.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return resp.StatusCode, m, raw
}

func (c *client) login(user, pass string) int {
	code, _, _ := c.do("POST", "/api/auth/login", map[string]string{"username": user, "password": pass})
	return code
}

func (e *env) account(name string, role auth.Role, regs ...string) {
	e.t.Helper()
	if _, err := e.auth.CreateLocal(auth.NewAccount{Username: name, Password: pw, Role: role, Registries: regs}); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) as(user string) *client {
	e.t.Helper()
	c := e.client()
	if code := c.login(user, pw); code != 200 {
		e.t.Fatalf("login %s: %d", user, code)
	}
	return c
}

func TestUnauthenticatedAndPublicRoutes(t *testing.T) {
	e := newEnv(t, nil)
	c := e.client()
	for _, r := range [][2]string{{"GET", "/api/registries"}, {"GET", "/api/fleet"}, {"GET", "/api/auth/me"}, {"GET", "/api/admin/audit"}, {"POST", "/api/registries/x/start"}} {
		if code, m, _ := c.do(r[0], r[1], nil); code != 401 || m["code"] != "unauthenticated" {
			t.Errorf("%v: %d %v", r, code, m)
		}
	}
	if code, _, _ := c.do("GET", "/api/healthz", nil); code != 200 {
		t.Error("healthz must be public")
	}
	if code, m, _ := c.do("GET", "/api/auth/config", nil); code != 200 || m["localLogin"] != true || m["oidc"] != false {
		t.Errorf("config: %d %v", code, m)
	}
}

func TestLoginCookieAndHeaders(t *testing.T) {
	e := newEnv(t, nil)
	e.account("alice", auth.Viewer)
	c := e.client()
	if code := c.login("alice", "wrong-password-12"); code != 401 {
		t.Fatalf("bad login: %d", code)
	}
	req, _ := http.NewRequest("POST", e.srv.URL+"/api/auth/login", strings.NewReader(`{"username":"alice","password":"`+pw+`"}`))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var sc *http.Cookie
	for _, ck := range resp.Cookies() {
		if ck.Name == cookieName {
			sc = ck
		}
	}
	if sc == nil || !sc.HttpOnly || sc.SameSite != http.SameSiteLaxMode || sc.Value == "" {
		t.Fatalf("session cookie: %+v", sc)
	}
	for h, want := range map[string]string{"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Cache-Control": "no-store"} {
		if resp.Header.Get(h) != want {
			t.Errorf("%s = %q", h, resp.Header.Get(h))
		}
	}
	if !strings.Contains(resp.Header.Get("Content-Security-Policy"), "default-src 'self'") {
		t.Error("CSP missing")
	}

	if c.login("alice", pw) != 200 {
		t.Fatal("login")
	}
	if code, m, _ := c.do("GET", "/api/auth/me", nil); code != 200 || m["username"] != "alice" || m["role"] != "viewer" {
		t.Fatalf("me: %d %v", code, m)
	}
	if code, _, _ := c.do("POST", "/api/auth/logout", nil); code != 204 {
		t.Fatalf("logout: %d", code)
	}
	if code, _, _ := c.do("GET", "/api/auth/me", nil); code != 401 {
		t.Fatalf("session must be dead after logout: %d", code)
	}
}

func TestRolesAndScope(t *testing.T) {
	e := newEnv(t, nil)
	e.account("root", auth.Admin)
	e.account("op", auth.Operator, "acme")
	e.account("view", auth.Viewer, "acme")
	root, op, view := e.as("root"), e.as("op"), e.as("view")

	for _, n := range []string{"acme", "globex"} {
		if code, m, _ := root.do("POST", "/api/registries", map[string]string{"name": n, "customer": n}); code != 201 {
			t.Fatalf("create %s: %d %v", n, code, m)
		}
	}
	// role limits
	if code, _, _ := op.do("POST", "/api/registries", map[string]string{"name": "x", "customer": "x"}); code != 403 {
		t.Errorf("operator must not create: %d", code)
	}
	if code, _, _ := op.do("DELETE", "/api/registries/acme", nil); code != 403 {
		t.Errorf("operator must not delete: %d", code)
	}
	if code, _, _ := view.do("POST", "/api/registries/acme/stop", nil); code != 403 {
		t.Errorf("viewer must not stop: %d", code)
	}
	if code, _, _ := view.do("GET", "/api/registries/acme/config", nil); code != 403 {
		t.Errorf("viewer must not read config (may hold secrets): %d", code)
	}
	if code, m, _ := op.do("POST", "/api/registries/acme/stop", nil); code != 200 || m["state"] != "stopped" {
		t.Errorf("operator stop: %d %v", code, m)
	}
	if code, _, _ := view.do("GET", "/api/registries/acme", nil); code != 200 {
		t.Errorf("viewer read: %d", code)
	}
	if code, _, _ := op.do("GET", "/api/admin/accounts", nil); code != 403 {
		t.Errorf("operator must not list accounts: %d", code)
	}

	// scope: globex is invisible, and indistinguishable from a missing registry
	for _, c := range []*client{op, view} {
		code, _, _ := c.do("GET", "/api/registries/globex", nil)
		missing, _, _ := c.do("GET", "/api/registries/nope", nil)
		if code != 404 || missing != 404 {
			t.Errorf("out-of-scope = %d, nonexistent = %d (both must be 404)", code, missing)
		}
	}
	if code, _, _ := op.do("POST", "/api/registries/globex/start", nil); code != 404 {
		t.Errorf("out-of-scope start: %d", code)
	}
	for _, path := range []string{"/api/registries", "/api/fleet"} {
		_, _, raw := op.do("GET", path, nil)
		if strings.Contains(string(raw), "globex") || !strings.Contains(string(raw), "acme") {
			t.Errorf("%s leaks or hides: %s", path, raw)
		}
	}
	_, _, raw := root.do("GET", "/api/fleet", nil)
	if !strings.Contains(string(raw), "globex") || !strings.Contains(string(raw), `"total":2`) {
		t.Errorf("admin fleet: %s", raw)
	}

	// deleting a registry revokes access for good: a new one with the same name starts clean
	if code, _, _ := root.do("DELETE", "/api/registries/acme", nil); code != 204 {
		t.Fatal("delete")
	}
	root.do("POST", "/api/registries", map[string]string{"name": "acme", "customer": "new owner"})
	if code, _, _ := op.do("GET", "/api/registries/acme", nil); code != 404 {
		t.Errorf("stale assignment resurrected access to a new registry: %d", code)
	}
}

func TestCrossOriginWritesRefused(t *testing.T) {
	e := newEnv(t, nil)
	e.account("root", auth.Admin)
	root := e.as("root")
	host := strings.TrimPrefix(e.srv.URL, "http://")
	if code, _, _ := root.do("POST", "/api/registries", map[string]string{"name": "a", "customer": "a"}, "Origin", "http://evil.example"); code != 403 {
		t.Errorf("cross-origin write allowed: %d", code)
	}
	if code, _, _ := root.do("POST", "/api/registries", map[string]string{"name": "a", "customer": "a"}, "Origin", "http://"+host); code != 201 {
		t.Errorf("same-origin write refused: %d", code)
	}
}

func TestForcedPasswordChange(t *testing.T) {
	e := newEnv(t, nil)
	if _, err := e.auth.CreateLocal(auth.NewAccount{Username: "newbie", Password: pw, Role: auth.Admin, MustChange: true}); err != nil {
		t.Fatal(err)
	}
	c := e.as("newbie")
	if code, m, _ := c.do("GET", "/api/registries", nil); code != 403 || m["code"] != "password_change_required" {
		t.Fatalf("gate: %d %v", code, m)
	}
	if code, m, _ := c.do("GET", "/api/auth/me", nil); code != 200 || m["mustChangePassword"] != true {
		t.Fatalf("me: %d %v", code, m)
	}
	if code, _, _ := c.do("POST", "/api/auth/password", map[string]string{"current": "nope-nope-nope", "new": "another-long-password"}); code != 400 {
		t.Fatalf("wrong current: %d", code)
	}
	if code, _, _ := c.do("POST", "/api/auth/password", map[string]string{"current": pw, "new": "another-long-password"}); code != 200 {
		t.Fatalf("change: %d", code)
	}
	if code, _, _ := c.do("GET", "/api/registries", nil); code != 200 {
		t.Fatalf("gate must lift after the change: %d", code)
	}
}

func TestAuditTrail(t *testing.T) {
	e := newEnv(t, nil)
	e.account("root", auth.Admin)
	e.account("view", auth.Viewer, "acme")
	root, view := e.as("root"), e.as("view")

	root.do("POST", "/api/registries", map[string]string{"name": "acme", "customer": "Acme", "username": "u1", "password": "super-secret-pw-1"})
	root.do("PUT", "/api/registries/acme/users/bob", map[string]string{"password": "bobs-secret-password"})
	view.do("POST", "/api/registries/acme/stop", nil) // denied
	e.client().login("root", "wrong-password-123")    // failed login

	_, m, raw := root.do("GET", "/api/admin/audit", nil)
	if strings.Contains(string(raw), "super-secret-pw-1") || strings.Contains(string(raw), "bobs-secret-password") || strings.Contains(string(raw), pw) {
		t.Fatalf("passwords leaked into the audit log: %s", raw)
	}
	type row struct{ actor, action, target, outcome string }
	var got []row
	for _, x := range m["entries"].([]any) {
		en := x.(map[string]any)
		got = append(got, row{en["actor"].(string), en["action"].(string), en["target"].(string), en["outcome"].(string)})
	}
	for _, want := range []row{
		{"root", "registry.create", "acme", "ok"},
		{"root", "registry.user.set", "acme", "ok"},
		{"view", "registry.stop", "acme", "denied"},
		{"root", "auth.login", "", "denied"},
		{"root", "auth.login", "", "ok"},
	} {
		found := false
		for _, g := range got {
			if g == want {
				found = true
			}
		}
		if !found {
			t.Errorf("missing audit row %+v in %+v", want, got)
		}
	}

	// not visible to non-admins
	if code, _, _ := view.do("GET", "/api/admin/audit", nil); code != 403 {
		t.Errorf("audit must be admin only: %d", code)
	}
	// filters + csv + cursor
	_, m, _ = root.do("GET", "/api/admin/audit?actor=view", nil)
	es := m["entries"].([]any) // the login and the denied stop
	if len(es) != 2 {
		t.Errorf("actor filter: %v", es)
	}
	for _, x := range es {
		if x.(map[string]any)["actor"] != "view" {
			t.Errorf("filter leaked another actor: %v", x)
		}
	}
	_, m, _ = root.do("GET", "/api/admin/audit?limit=2", nil)
	if m["next"].(float64) == 0 || len(m["entries"].([]any)) != 2 {
		t.Errorf("cursor: %v", m)
	}
	code, _, csv := root.do("GET", "/api/admin/audit?format=csv", nil)
	if code != 200 || !strings.HasPrefix(string(csv), "id,time,actor,role,action,target,outcome,ip,detail") || !strings.Contains(string(csv), "registry.create") {
		t.Errorf("csv: %d %.120s", code, csv)
	}
	if code, _, _ := root.do("GET", "/api/admin/audit?since=yesterday", nil); code != 400 {
		t.Errorf("bad since: %d", code)
	}
}

func TestCSVFormulaInjectionDefused(t *testing.T) {
	for in, want := range map[string]string{"=cmd()": "'=cmd()", "+1": "'+1", "-1": "'-1", "@x": "'@x", "plain": "plain", "": ""} {
		if got := csvSafe(in); got != want {
			t.Errorf("%q -> %q", in, got)
		}
	}
}

func TestAccountAdministration(t *testing.T) {
	e := newEnv(t, nil)
	e.account("root", auth.Admin)
	root := e.as("root")

	code, m, _ := root.do("POST", "/api/admin/accounts", map[string]any{"username": "dev", "password": pw, "role": "viewer", "registries": []string{"acme"}})
	if code != 201 {
		t.Fatalf("create: %d %v", code, m)
	}
	id := int(m["id"].(float64))
	path := "/api/admin/accounts/" + strings.TrimSpace(itoa(int64(id)))
	if _, m, raw := root.do("GET", "/api/admin/accounts", nil); strings.Contains(string(raw), "passwordHash") || strings.Contains(string(raw), "$2a$") || m == nil && len(raw) == 0 {
		t.Fatalf("account list leaks hashes: %s", raw)
	}
	if code, m, _ := root.do("PATCH", path, map[string]any{"role": "operator"}); code != 200 || m["role"] != "operator" {
		t.Fatalf("patch: %d %v", code, m)
	}
	if code, _, _ := root.do("PATCH", path, map[string]any{"role": "emperor"}); code != 400 {
		t.Fatalf("bad role: %d", code)
	}
	if code, _, _ := root.do("POST", path+"/password", map[string]any{"password": "short"}); code != 400 {
		t.Fatalf("weak reset: %d", code)
	}
	if code, _, _ := root.do("POST", path+"/password", map[string]any{"password": "fresh-long-password-1", "mustChangePassword": true}); code != 200 {
		t.Fatalf("reset: %d", code)
	}
	if code, _, _ := root.do("DELETE", path, nil); code != 204 {
		t.Fatalf("delete: %d", code)
	}
	if code, _, _ := root.do("DELETE", path, nil); code != 404 {
		t.Fatalf("delete twice: %d", code)
	}

	// self-protection and last-admin guard
	_, me, _ := root.do("GET", "/api/auth/me", nil)
	self := "/api/admin/accounts/" + itoa(int64(me["id"].(float64)))
	if code, _, _ := root.do("DELETE", self, nil); code != 409 {
		t.Errorf("self delete: %d", code)
	}
	if code, _, _ := root.do("PATCH", self, map[string]any{"role": "viewer"}); code != 409 {
		t.Errorf("self demote as last admin: %d", code)
	}
	if code, _, _ := root.do("GET", "/api/admin/accounts/abc/x", nil); code != 404 {
		t.Errorf("garbage id: %d", code)
	}
}

func TestLoginLockoutReturns429(t *testing.T) {
	e := newEnv(t, nil)
	e.account("alice", auth.Viewer)
	c := e.client()
	for i := 0; i < 5; i++ {
		c.login("alice", "wrong-password-12")
	}
	req, _ := http.NewRequest("POST", e.srv.URL+"/api/auth/login", strings.NewReader(`{"username":"alice","password":"`+pw+`"}`))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 429 || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("want 429 with Retry-After, got %d %q", resp.StatusCode, resp.Header.Get("Retry-After"))
	}
}

func TestLocalLoginCanBeDisabled(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.DisableLocalLogin = true })
	e.account("alice", auth.Viewer)
	if code := e.client().login("alice", pw); code != 403 {
		t.Fatalf("local login must be refused: %d", code)
	}
	if _, m, _ := e.client().do("GET", "/api/auth/config", nil); m["localLogin"] != false {
		t.Fatalf("config: %v", m)
	}
}
