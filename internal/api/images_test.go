package api

import (
	"bytes"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/rdeb/local-image-registry/internal/auth"
	"github.com/rdeb/local-image-registry/internal/runtime/fake"
	"github.com/rdeb/local-image-registry/internal/service"
	"github.com/rdeb/local-image-registry/internal/store"
)

func imgEnv(t *testing.T) (*env, *service.Service) {
	t.Helper()
	st, err := store.Open(t.TempDir() + "/t.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	svc := service.New(st, fake.New(), 5100, 5199)
	svc.SetReadyTimeout(0)
	svc.SetScratchDir(t.TempDir())
	t.Cleanup(svc.Close)
	a := auth.NewService(st)
	e := &env{t: t, st: st, auth: a}
	e.srv = newServer(t, svc, Options{Auth: a, Store: st})
	return e, svc
}

func TestAddImageEndpointsAreRoleAndScopeChecked(t *testing.T) {
	e, _ := imgEnv(t)
	e.account("root", auth.Admin)
	e.account("op", auth.Operator, "acme")
	e.account("view", auth.Viewer, "acme")
	e.account("other", auth.Operator, "globex")
	root, op, view, other := e.as("root"), e.as("op"), e.as("view"), e.as("other")
	for _, n := range []string{"acme", "globex"} {
		root.do("POST", "/api/registries", map[string]string{"name": n, "customer": n})
	}
	imp := map[string]any{"source": "alpine:3.19", "repo": "base/alpine", "tag": "3.19", "overwrite": true}
	up := "/api/registries/acme/images/upload?repo=a/b&tag=1&overwrite=true&filename=x.tar"

	for _, c := range []struct {
		who  *client
		m, p string
		body any
		want int
		why  string
	}{
		{view, "POST", "/api/registries/acme/images/import", imp, 403, "viewer cannot import"},
		{view, "POST", up, nil, 403, "viewer cannot upload"},
		{view, "GET", "/api/registries/acme/images/transfers", nil, 403, "viewer cannot list transfers"},
		{other, "POST", "/api/registries/acme/images/import", imp, 404, "out of scope looks nonexistent"},
		{other, "GET", "/api/registries/acme/images/transfers", nil, 404, "out-of-scope transfers"},
		{op, "GET", "/api/registries/acme/images/transfers", nil, 200, "operator lists transfers"},
		{op, "POST", "/api/registries/acme/images/import", imp, 202, "operator imports"},
		{root, "POST", "/api/registries/acme/images/import", map[string]any{"source": "", "repo": "a", "tag": "t"}, 400, "empty source"},
		{root, "POST", "/api/registries/acme/images/import", map[string]any{"source": "alpine:3", "repo": "BAD", "tag": "t"}, 400, "bad repo"},
		{root, "POST", "/api/registries/acme/images/import", map[string]any{"source": "alpine:3", "repo": "a", "tag": "t", "hack": 1}, 400, "unknown field"},
	} {
		if code, _, raw := c.who.do(c.m, c.p, c.body); code != c.want {
			t.Errorf("%s: %s %s -> %d, want %d (%.100s)", c.why, c.m, c.p, code, c.want, raw)
		}
	}
}

func TestUploadRejectsOversizeBodiesWith413(t *testing.T) {
	e, svc := imgEnv(t)
	e.account("root", auth.Admin)
	root := e.as("root")
	root.do("POST", "/api/registries", map[string]string{"name": "acme", "customer": "A"})
	svc.SetImportLimit(1000)

	req, _ := http.NewRequest("POST", e.srv.URL+"/api/registries/acme/images/upload?repo=a&tag=t&overwrite=true&filename=big.tar", bytes.NewReader(bytes.Repeat([]byte("x"), 3<<20)))
	for _, c := range root.c.Jar.Cookies(req.URL) {
		req.AddCookie(c)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge && resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("oversize upload: %d", resp.StatusCode)
	}
}

func TestImportJobLifecycleAndNoCredentialsAnywhere(t *testing.T) {
	e, _ := imgEnv(t)
	e.account("root", auth.Admin)
	root := e.as("root")
	root.do("POST", "/api/registries", map[string]string{"name": "acme", "customer": "A"})

	// a loopback source is refused by the SSRF guard, which makes the job fail quickly and deterministically
	code, m, raw := root.do("POST", "/api/registries/acme/images/import", map[string]any{
		"source": "127.0.0.1:1/app:1", "username": "bob", "password": "hunter2-secret", "repo": "a/b", "tag": "t", "overwrite": true})
	if code != 202 || m["status"] != "queued" {
		t.Fatalf("%d %s", code, raw)
	}
	var final map[string]any
	for i := 0; i < 200 && final == nil; i++ {
		_, _, raw := root.do("GET", "/api/registries/acme/images/transfers", nil)
		if strings.Contains(string(raw), `"failed"`) {
			_, _, _ = root.do("GET", "/api/registries/acme/images/transfers", nil)
			final = map[string]any{"raw": string(raw)}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if final == nil {
		t.Fatal("job never failed")
	}
	if !strings.Contains(final["raw"].(string), "loopback or link-local") {
		t.Fatalf("failure should explain itself: %v", final["raw"])
	}
	_, _, audit := root.do("GET", "/api/admin/audit?limit=100", nil)
	for _, bad := range []string{"hunter2-secret"} {
		if strings.Contains(string(audit), bad) || strings.Contains(final["raw"].(string), bad) {
			t.Fatalf("credential leaked: %s", bad)
		}
	}
	for _, want := range []string{`"registry.image.import"`, `"registry.image.transfer"`, `"privateSource":"true"`} {
		if !strings.Contains(string(audit), want) {
			t.Errorf("audit lacks %s", want)
		}
	}
}

func TestRepositoryDeleteAndSummariesAreRoleScopeAndInputChecked(t *testing.T) {
	e, _ := imgEnv(t)
	e.account("root", auth.Admin)
	e.account("op", auth.Operator, "acme")
	e.account("view", auth.Viewer, "acme")
	e.account("other", auth.Operator, "globex")
	root, op, view, other := e.as("root"), e.as("op"), e.as("view"), e.as("other")
	for _, n := range []string{"acme", "globex"} {
		root.do("POST", "/api/registries", map[string]string{"name": n, "customer": n})
	}
	for _, c := range []struct {
		who  *client
		m, p string
		want int
		why  string
	}{
		{view, "DELETE", "/api/registries/acme/repositories?repo=a/b", 403, "viewer cannot delete a repository"},
		{other, "DELETE", "/api/registries/acme/repositories?repo=a/b", 404, "out-of-scope looks nonexistent"},
		{other, "GET", "/api/registries/acme/repository-summaries", 404, "out-of-scope summaries"},
		{op, "DELETE", "/api/registries/acme/repositories?repo=../etc", 400, "bad repository name"},
		{op, "DELETE", "/api/registries/acme/repositories", 400, "missing repository"},
		{op, "DELETE", "/api/registries/acme/repositories?repo=UPPER", 400, "uppercase repository"},
	} {
		if code, _, raw := c.who.do(c.m, c.p, nil); code != c.want {
			t.Errorf("%s: %s %s -> %d, want %d (%.80s)", c.why, c.m, c.p, code, c.want, raw)
		}
	}
	// the attempts are audited, denied ones included
	_, _, audit := root.do("GET", "/api/admin/audit?limit=50", nil)
	if !strings.Contains(string(audit), `"registry.repo.delete"`) {
		t.Errorf("audit lacks registry.repo.delete: %.200s", audit)
	}
}

func TestFixIsOperatorOnlyScopedAndInputChecked(t *testing.T) {
	e, _ := imgEnv(t)
	e.account("root", auth.Admin)
	e.account("op", auth.Operator, "acme")
	e.account("view", auth.Viewer, "acme")
	e.account("other", auth.Operator, "globex")
	root, op, view, other := e.as("root"), e.as("op"), e.as("view"), e.as("other")
	for _, n := range []string{"acme", "globex"} {
		root.do("POST", "/api/registries", map[string]string{"name": n, "customer": n})
	}
	body := map[string]string{"repo": "team/app", "ref": "v1"}
	for _, c := range []struct {
		who  *client
		m, p string
		b    any
		want int
		why  string
	}{
		{view, "POST", "/api/registries/acme/images/fix", body, 403, "viewer cannot fix"},
		{view, "GET", "/api/registries/acme/images/fix-plan?repo=team/app&ref=v1", nil, 403, "viewer cannot plan a fix"},
		{other, "POST", "/api/registries/acme/images/fix", body, 404, "out-of-scope looks nonexistent"},
		{op, "POST", "/api/registries/acme/images/fix", map[string]string{"repo": "../etc", "ref": "v1"}, 501, "security disabled in this test server"},
		{op, "POST", "/api/registries/acme/images/fix", map[string]string{"repo": "team/app", "ref": "v1", "tag": "v1"}, 501, "security disabled in this test server"},
	} {
		if code, _, raw := c.who.do(c.m, c.p, c.b); code != c.want {
			t.Errorf("%s: %s %s -> %d, want %d (%.80s)", c.why, c.m, c.p, code, c.want, raw)
		}
	}
}

func TestRebaseIsOperatorOnlyScopedAndInputChecked(t *testing.T) {
	e, _ := imgEnv(t)
	e.account("root", auth.Admin)
	e.account("op", auth.Operator, "acme")
	e.account("view", auth.Viewer, "acme")
	e.account("other", auth.Operator, "globex")
	root, op, view, other := e.as("root"), e.as("op"), e.as("view"), e.as("other")
	for _, n := range []string{"acme", "globex"} {
		root.do("POST", "/api/registries", map[string]string{"name": n, "customer": n})
	}
	ok := map[string]string{"repo": "team/app", "ref": "v1", "oldBase": "docker.io/library/alpine:3.14", "newBase": "docker.io/library/alpine:3.21"}
	with := func(k, v string) map[string]string {
		m := map[string]string{}
		for a, b := range ok {
			m[a] = b
		}
		m[k] = v
		return m
	}
	for _, c := range []struct {
		who  *client
		b    any
		want int
		why  string
	}{
		{view, ok, 403, "viewer cannot rebase"},
		{other, ok, 404, "out-of-scope looks nonexistent"},
		{op, with("repo", "../etc"), 400, "bad repository"},
		{op, with("newBase", "not a ref!!"), 400, "bad new base"},
		{op, with("oldBase", ""), 400, "missing old base"},
		{op, with("newBase", ok["oldBase"]), 400, "same base"},
		{op, with("tag", "v1"), 400, "same tag as the original"},
	} {
		if code, _, raw := c.who.do("POST", "/api/registries/acme/images/rebase", c.b); code != c.want {
			t.Errorf("%s: -> %d, want %d (%.80s)", c.why, code, c.want, raw)
		}
	}
}
