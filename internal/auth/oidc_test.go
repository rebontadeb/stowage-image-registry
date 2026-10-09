package auth

import (
	"context"
	"strings"
	"testing"

	"github.com/rdeb/local-image-registry/internal/auth/authtest"
)

func newOIDCFor(t *testing.T, f *authtest.IdP, mod func(*OIDCConfig)) *OIDC {
	t.Helper()
	cfg := OIDCConfig{
		Issuer: f.URL(), ClientID: "mgr", ClientSecret: "s", RedirectURL: "http://mgr/cb",
		AdminGroups: []string{"reg-admins"}, OperatorGroups: []string{"reg-ops"}, ViewerGroups: []string{"reg-view"},
	}
	if mod != nil {
		mod(&cfg)
	}
	o, err := NewOIDC(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func TestOIDCHappyPathAndRoleMapping(t *testing.T) {
	f := authtest.New(t)
	o := newOIDCFor(t, f, nil)
	ctx := context.Background()

	for _, c := range []struct {
		groups []any
		want   Role
	}{
		{[]any{"reg-view"}, Viewer},
		{[]any{"reg-view", "reg-ops"}, Operator},
		{[]any{"other", "reg-admins", "reg-ops"}, Admin},
	} {
		u, err := o.Start(ctx)
		if err != nil {
			t.Fatal(err)
		}
		state, code := f.Authorize(t, u, map[string]any{"sub": "u1", "preferred_username": "dana", "name": "Dana D", "groups": c.groups})
		id, err := o.Finish(ctx, state, code)
		if err != nil || id.Role != c.want || id.Username != "dana" || id.DisplayName != "Dana D" {
			t.Fatalf("%v: %+v %v", c.groups, id, err)
		}
		if !strings.HasPrefix(id.Subject, f.URL()+"#") {
			t.Fatalf("subject must be namespaced by issuer: %q", id.Subject)
		}
	}
}

func TestOIDCRejections(t *testing.T) {
	f := authtest.New(t)
	o := newOIDCFor(t, f, nil)
	ctx := context.Background()
	good := map[string]any{"sub": "u1", "preferred_username": "dana", "groups": []any{"reg-ops"}}

	// unknown / replayed state
	if _, err := o.Finish(ctx, "nope", "code"); err != ErrOIDCState {
		t.Fatalf("unknown state: %v", err)
	}
	u, _ := o.Start(ctx)
	state, code := f.Authorize(t, u, good)
	if _, err := o.Finish(ctx, state, code); err != nil {
		t.Fatal(err)
	}
	if _, err := o.Finish(ctx, state, code); err != ErrOIDCState {
		t.Fatalf("state must be single use: %v", err)
	}

	// nobody in a mapped group
	u, _ = o.Start(ctx)
	state, code = f.Authorize(t, u, map[string]any{"sub": "u2", "preferred_username": "eve", "groups": []any{"unrelated"}})
	if _, err := o.Finish(ctx, state, code); err != ErrNoRole {
		t.Fatalf("no role: %v", err)
	}

	// IdP echoes a different nonce (token replay / injection)
	f.NonceOverride = "attacker-nonce"
	u, _ = o.Start(ctx)
	state, code = f.Authorize(t, u, good)
	if _, err := o.Finish(ctx, state, code); err == nil || !strings.Contains(err.Error(), "nonce") {
		t.Fatalf("nonce mismatch accepted: %v", err)
	}
	f.NonceOverride = ""

	// token minted for another client
	f.Audience = "someone-else"
	u, _ = o.Start(ctx)
	state, code = f.Authorize(t, u, good)
	if _, err := o.Finish(ctx, state, code); err == nil {
		t.Fatal("wrong audience accepted")
	}
	f.Audience = ""

	// stolen code without the matching PKCE verifier is useless: swap states
	u1, _ := o.Start(ctx)
	u2, _ := o.Start(ctx)
	s1, c1 := f.Authorize(t, u1, good)
	s2, _ := f.Authorize(t, u2, good)
	_ = s1
	if _, err := o.Finish(ctx, s2, c1); err == nil {
		t.Fatal("code redeemed with another session's verifier")
	}
}

func TestOIDCDefaultRoleAndUsernameFallback(t *testing.T) {
	f := authtest.New(t)
	o := newOIDCFor(t, f, func(c *OIDCConfig) { c.DefaultRole = Viewer; c.GroupsClaim = "roles" })
	ctx := context.Background()
	u, _ := o.Start(ctx)
	// no preferred_username and an invalid one with a space: falls back to email
	state, code := f.Authorize(t, u, map[string]any{"sub": "u3", "preferred_username": "has space", "email": "fran@example.com", "roles": "x y"})
	id, err := o.Finish(ctx, state, code)
	if err != nil || id.Role != Viewer || id.Username != "fran@example.com" {
		t.Fatalf("%+v %v", id, err)
	}
}

func TestOIDCConfigValidation(t *testing.T) {
	for name, cfg := range map[string]OIDCConfig{
		"missing issuer":  {ClientID: "c", RedirectURL: "r", AdminGroups: []string{"g"}},
		"no role mapping": {Issuer: "i", ClientID: "c", RedirectURL: "r"},
		"bad default":     {Issuer: "i", ClientID: "c", RedirectURL: "r", DefaultRole: "root"},
	} {
		if _, err := NewOIDC(cfg); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestOIDCStartFailsCleanlyWhenIdPDown(t *testing.T) {
	f := authtest.New(t)
	o := newOIDCFor(t, f, nil)
	f.Server.Close()
	if _, err := o.Start(context.Background()); err == nil {
		t.Fatal("want discovery error")
	}
}
