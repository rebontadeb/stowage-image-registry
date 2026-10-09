package api

import (
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"

	"github.com/rdeb/local-image-registry/internal/auth"
	"github.com/rdeb/local-image-registry/internal/auth/authtest"
)

// oidcEnv wires the manager to a fake identity provider.
func oidcEnv(t *testing.T) (*env, *authtest.IdP) {
	idp := authtest.New(t)
	var e *env
	e = newEnv(t, func(o *Options) {
		oc, err := auth.NewOIDC(auth.OIDCConfig{
			Issuer: idp.URL(), ClientID: "mgr", ClientSecret: "s", RedirectURL: "http://manager/api/auth/oidc/callback",
			DisplayName: "Corp SSO", AdminGroups: []string{"reg-admins"}, OperatorGroups: []string{"reg-ops"}, ViewerGroups: []string{"reg-view"},
		})
		if err != nil {
			t.Fatal(err)
		}
		o.OIDC = oc
	})
	return e, idp
}

// browse runs the redirect dance as a browser would and returns the callback response.
func browse(t *testing.T, e *env, idp *authtest.IdP, c *client, claims map[string]any) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("GET", e.srv.URL+"/api/auth/oidc/login", nil)
	resp, err := c.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("login start: %d", resp.StatusCode)
	}
	state, code := idp.Authorize(t, resp.Header.Get("Location"), claims)
	req, _ = http.NewRequest("GET", e.srv.URL+"/api/auth/oidc/callback?state="+url.QueryEscape(state)+"&code="+url.QueryEscape(code), nil)
	resp, err = c.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp
}

func TestOIDCSignInEndToEnd(t *testing.T) {
	e, idp := oidcEnv(t)
	c := e.client()

	if _, m, _ := c.do("GET", "/api/auth/config", nil); m["oidc"] != true || m["oidcName"] != "Corp SSO" {
		t.Fatalf("config: %v", m)
	}
	resp := browse(t, e, idp, c, map[string]any{"sub": "u1", "preferred_username": "dana", "name": "Dana D", "groups": []any{"reg-ops"}})
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/" {
		t.Fatalf("callback: %d -> %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	var sc *http.Cookie
	for _, ck := range resp.Cookies() {
		if ck.Name == cookieName {
			sc = ck
		}
	}
	if sc == nil || !sc.HttpOnly || sc.Value == "" {
		t.Fatalf("session cookie: %+v", sc)
	}
	code, m, _ := c.do("GET", "/api/auth/me", nil)
	if code != 200 || m["username"] != "dana" || m["role"] != "operator" || m["source"] != "oidc" {
		t.Fatalf("me: %d %v", code, m)
	}
	// SSO accounts have no local password
	if code := e.client().login("dana", "anything-at-all-123"); code != 401 {
		t.Fatalf("local login for SSO account: %d", code)
	}

	// an admin assigns scope; role follows the IdP on the next sign-in
	e.account("root", auth.Admin)
	root := e.as("root")
	root.do("POST", "/api/registries", map[string]string{"name": "acme", "customer": "A"})
	jar, _ := cookiejar.New(nil)
	c2 := &client{e: e, c: &http.Client{Jar: jar, CheckRedirect: c.c.CheckRedirect}}
	browse(t, e, idp, c2, map[string]any{"sub": "u1", "preferred_username": "dana", "groups": []any{"reg-view"}})
	if _, m, _ := c2.do("GET", "/api/auth/me", nil); m["role"] != "viewer" {
		t.Fatalf("role not synced from IdP: %v", m)
	}

	// audit records both SSO sign-ins and the refused local-password attempt, each with its method
	_, _, raw := root.do("GET", "/api/admin/audit?actor=dana", nil)
	if n := strings.Count(string(raw), `"method":"oidc"`); n != 2 {
		t.Fatalf("want 2 oidc sign-ins in the audit log, got %d: %s", n, raw)
	}
	if !strings.Contains(string(raw), `"method":"local","reason":"bad credentials"`) {
		t.Fatalf("local attempt not audited: %s", raw)
	}
}

func TestOIDCDeniesUnmappedUserAndBadCallbacks(t *testing.T) {
	e, idp := oidcEnv(t)
	c := e.client()

	resp := browse(t, e, idp, c, map[string]any{"sub": "u2", "preferred_username": "eve", "groups": []any{"nobody"}})
	loc := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusFound || !strings.HasPrefix(loc, "/#/login?error=") || !strings.Contains(loc, "not+authorised") && !strings.Contains(loc, "not%20authorised") {
		t.Fatalf("unmapped user must be sent back to the login page with a reason: %d %q", resp.StatusCode, loc)
	}
	if code, _, _ := c.do("GET", "/api/auth/me", nil); code != 401 {
		t.Fatalf("denied user got a session: %d", code)
	}

	// forged / replayed callbacks
	for _, q := range []string{"state=bogus&code=x", "error=access_denied", "", "state=&code="} {
		req, _ := http.NewRequest("GET", e.srv.URL+"/api/auth/oidc/callback?"+q, nil)
		r, err := c.c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		if r.StatusCode != http.StatusFound || !strings.HasPrefix(r.Header.Get("Location"), "/#/login?error=") {
			t.Errorf("callback ?%s: %d %q", q, r.StatusCode, r.Header.Get("Location"))
		}
	}
	if code, _, _ := c.do("GET", "/api/auth/me", nil); code != 401 {
		t.Fatalf("bad callback produced a session: %d", code)
	}

	// failures are audited, with the reason but no tokens
	e.account("root", auth.Admin)
	_, _, raw := e.as("root").do("GET", "/api/admin/audit?outcome=denied", nil)
	if !strings.Contains(string(raw), `"method":"oidc"`) || strings.Contains(string(raw), "id_token") {
		t.Fatalf("audit of failed SSO: %s", raw)
	}
}

func TestOIDCRoutesAre404WhenNotConfigured(t *testing.T) {
	e := newEnv(t, nil)
	for _, p := range []string{"/api/auth/oidc/login", "/api/auth/oidc/callback?state=a&code=b"} {
		if code, _, _ := e.client().do("GET", p, nil); code != 404 {
			t.Errorf("%s: %d", p, code)
		}
	}
}

func TestSSOOnlyModeBlocksLocalPasswordsButNotSSO(t *testing.T) {
	idp := authtest.New(t)
	e := newEnv(t, func(o *Options) {
		oc, _ := auth.NewOIDC(auth.OIDCConfig{Issuer: idp.URL(), ClientID: "mgr", RedirectURL: "http://m/cb", AdminGroups: []string{"a"}})
		o.OIDC, o.DisableLocalLogin = oc, true
	})
	e.account("alice", auth.Viewer)
	c := e.client()
	if code := c.login("alice", pw); code != 403 {
		t.Fatalf("local login in SSO-only mode: %d", code)
	}
	browse(t, e, idp, c, map[string]any{"sub": "s1", "preferred_username": "sso-admin", "groups": []any{"a"}})
	if code, m, _ := c.do("GET", "/api/auth/me", nil); code != 200 || m["role"] != "admin" {
		t.Fatalf("sso sign-in in SSO-only mode: %d %v", code, m)
	}
}
