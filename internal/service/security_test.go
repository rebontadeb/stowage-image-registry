package service

import (
	"context"
	"crypto/tls"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/rdeb/local-image-registry/internal/runtime"
)

func fileContent(sp runtime.Spec, path string) (string, bool) {
	for _, f := range sp.Files {
		if f.Path == path {
			return string(f.Content), true
		}
	}
	return "", false
}

func TestUsersRenderHtpasswdAndKeepRunState(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	s := newSvc(t, f, 5100, 5199)
	if _, err := s.Create(ctx, CreateInput{Name: "acme", Customer: "x", Username: "alice", Password: "s3cretpass"}); err != nil {
		t.Fatal(err)
	}
	ht, ok := fileContent(f.specs["acme"], htpasswdPath)
	if !ok || !strings.HasPrefix(ht, "_admin:$2") || !strings.Contains(ht, "alice:$2") {
		t.Fatalf("htpasswd: %q", ht)
	}
	if f.specs["acme"].Env["REGISTRY_AUTH"] != "htpasswd" {
		t.Fatalf("env: %v", f.specs["acme"].Env)
	}

	if err := s.SetUser(ctx, "acme", "bob", "anotherpass1"); err != nil {
		t.Fatal(err)
	}
	if names, _ := s.Users(ctx, "acme"); len(names) != 2 {
		t.Fatalf("users: %v", names)
	}
	// password change keeps a single entry and rotates the hash
	before, _ := fileContent(f.specs["acme"], htpasswdPath)
	if err := s.SetUser(ctx, "acme", "bob", "changedpass22"); err != nil {
		t.Fatal(err)
	}
	after, _ := fileContent(f.specs["acme"], htpasswdPath)
	if before == after || strings.Count(after, "bob:") != 1 {
		t.Fatalf("password change: %q", after)
	}
	if f.state["acme"] != runtime.StateRunning {
		t.Fatal("registry should stay running")
	}

	if err := s.RemoveUser(ctx, "acme", "bob"); err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveUser(ctx, "acme", "bob"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}

	// stopped stays stopped across a change
	s.Stop(ctx, "acme")
	if err := s.SetUser(ctx, "acme", "carol", "yetanotherpw"); err != nil {
		t.Fatal(err)
	}
	if f.state["acme"] != runtime.StateStopped {
		t.Fatal("stopped registry must stay stopped")
	}
}

func TestUserValidation(t *testing.T) {
	ctx := context.Background()
	s := newSvc(t, newFake(), 5100, 5199)
	s.Create(ctx, CreateInput{Name: "acme", Customer: "x"})
	for _, c := range [][2]string{{"_admin", "longenough1"}, {"bad name", "longenough1"}, {"ok", "short"}, {"ok", strings.Repeat("x", 73)}, {"a:b", "longenough1"}} {
		if err := s.SetUser(ctx, "acme", c[0], c[1]); !errors.Is(err, ErrInvalid) {
			t.Errorf("%q/%d: want ErrInvalid, got %v", c[0], len(c[1]), err)
		}
	}
	if _, err := s.Create(ctx, CreateInput{Name: "other", Customer: "x", Username: "solo"}); !errors.Is(err, ErrInvalid) {
		t.Errorf("user without password: %v", err)
	}
}

func TestMutateRollsBackWhenRecreateFails(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	s := newSvc(t, f, 5100, 5199)
	s.Create(ctx, CreateInput{Name: "acme", Customer: "x"}) // Create call #1
	f.failNth = f.creates + 1                               // next Create (the mutation) fails

	if err := s.SetUser(ctx, "acme", "alice", "s3cretpass"); err == nil {
		t.Fatal("want error")
	}
	if names, _ := s.Users(ctx, "acme"); len(names) != 0 {
		t.Fatalf("user not rolled back: %v", names)
	}
	if f.state["acme"] != runtime.StateRunning {
		t.Fatalf("old state not restored: %v", f.state)
	}
}

func TestSelfSignedTLS(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	s := newSvc(t, f, 5100, 5199)
	s.Create(ctx, CreateInput{Name: "acme", Customer: "x"})

	info, err := s.SetTLS(ctx, "acme", TLSInput{Generate: true, Hosts: []string{"reg.example.com", "10.0.0.5"}})
	if err != nil || !info.Enabled || !info.SelfSign {
		t.Fatalf("%+v %v", info, err)
	}
	has := map[string]bool{}
	for _, n := range info.DNSNames {
		has[n] = true
	}
	if !has["localhost"] || !has["reg.example.com"] {
		t.Fatalf("SANs: %v", info.DNSNames)
	}
	sp := f.specs["acme"]
	crt, _ := fileContent(sp, certPath)
	key, _ := fileContent(sp, keyPath)
	if _, err := tls.X509KeyPair([]byte(crt), []byte(key)); err != nil {
		t.Fatal(err)
	}
	if sp.Env["REGISTRY_HTTP_TLS_CERTIFICATE"] != certPath {
		t.Fatalf("env: %v", sp.Env)
	}
	if v, _ := s.Get(ctx, "acme"); !v.TLS || !strings.HasPrefix(v.URL, "https://") {
		t.Fatalf("view: %+v", v)
	}

	if _, err := s.SetTLS(ctx, "acme", TLSInput{Cert: "junk", Key: "junk"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("want ErrInvalid, got %v", err)
	}

	if err := s.RemoveTLS(ctx, "acme"); err != nil {
		t.Fatal(err)
	}
	if _, ok := fileContent(f.specs["acme"], keyPath); ok {
		t.Fatal("key still mounted after removal")
	}
}

func TestConfigValidation(t *testing.T) {
	bad := map[string]string{
		"not yaml":        "a: [",
		"no version":      "storage: {}",
		"wrong root":      strings.Replace(DefaultConfig, "/var/lib/registry", "/tmp/x", 1),
		"delete disabled": strings.Replace(DefaultConfig, "enabled: true", "enabled: false", 1),
		"wrong port":      strings.Replace(DefaultConfig, ":5000", ":6000", 1),
		"auth section":    DefaultConfig + "auth:\n  silly:\n    realm: x\n",
		"tls section":     DefaultConfig + "  tls:\n    certificate: /x\n",
		"empty":           "# nothing\n",
	}
	for name, cfg := range bad {
		if err := validateConfig(cfg); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: want ErrInvalid, got %v", name, err)
		}
	}
	if err := validateConfig(DefaultConfig); err != nil {
		t.Fatalf("default config rejected: %v", err)
	}
}

func TestConfigAndEnvApplied(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	s := newSvc(t, f, 5100, 5199)
	s.Create(ctx, CreateInput{Name: "acme", Customer: "x"})

	custom := strings.Replace(DefaultConfig, "60s", "30s", 1)
	v, err := s.SetConfig(ctx, "acme", ConfigInput{Config: custom, Env: map[string]string{"REGISTRY_LOG_LEVEL": "debug"}})
	if err != nil || !v.Custom || v.Env["REGISTRY_LOG_LEVEL"] != "debug" {
		t.Fatalf("%+v %v", v, err)
	}
	if got, ok := fileContent(f.specs["acme"], configPath); !ok || got != custom {
		t.Fatalf("config not mounted: %v", ok)
	}
	if f.specs["acme"].Env["REGISTRY_LOG_LEVEL"] != "debug" {
		t.Fatal("env override missing")
	}

	for _, env := range []map[string]string{
		{"lower": "x"}, {"REGISTRY_AUTH": "none"}, {"REGISTRY_HTTP_TLS_KEY": "/x"},
		{"REGISTRY_STORAGE_FILESYSTEM_ROOTDIRECTORY": "/tmp"}, {"REGISTRY_HTTP_ADDR": ":1"},
	} {
		if _, err := s.SetConfig(ctx, "acme", ConfigInput{Env: env}); !errors.Is(err, ErrInvalid) {
			t.Errorf("%v: want ErrInvalid, got %v", env, err)
		}
	}

	// empty config resets to default (no mounted config file)
	v, err = s.SetConfig(ctx, "acme", ConfigInput{})
	if err != nil || v.Custom || v.Config != DefaultConfig {
		t.Fatalf("reset: %+v %v", v, err)
	}
	if _, ok := fileContent(f.specs["acme"], configPath); ok {
		t.Fatal("config still mounted after reset")
	}
}

func TestAdminHashMatchesStoredPassword(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	s := newSvc(t, f, 5100, 5199)
	s.Create(ctx, CreateInput{Name: "acme", Customer: "x"})
	rec, _ := s.st.Get("acme")
	ht, _ := fileContent(f.specs["acme"], htpasswdPath)
	hash := strings.TrimSpace(strings.TrimPrefix(strings.Split(ht, "\n")[0], "_admin:"))
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(rec.AdminPass)) != nil {
		t.Fatal("admin hash does not match stored admin password")
	}
}
