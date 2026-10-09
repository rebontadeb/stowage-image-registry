package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

var (
	ErrOIDCState = errors.New("sign-in session expired or invalid; start again")
	ErrNoRole    = errors.New("your account is not authorised: it is not in any group mapped to a role")
)

type OIDCConfig struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string   // https://<manager>/api/auth/oidc/callback
	Scopes       []string // default: openid profile email groups
	GroupsClaim  string   // default: groups
	DisplayName  string   // label for the sign-in button
	// Group names (exact match) that grant each role; the highest matching role wins.
	AdminGroups, OperatorGroups, ViewerGroups []string
	DefaultRole                               Role // used when no group matches; empty = deny
	HTTPClient                                *http.Client
}

type pending struct {
	nonce    string
	verifier string
	created  time.Time
}

type OIDC struct {
	cfg OIDCConfig

	mu       sync.Mutex
	provider *oidc.Provider
	oauth    *oauth2.Config
	pend     map[string]pending
}

func NewOIDC(cfg OIDCConfig) (*OIDC, error) {
	switch {
	case cfg.Issuer == "" || cfg.ClientID == "" || cfg.RedirectURL == "":
		return nil, errors.New("oidc: issuer, client id and redirect URL are required")
	case len(cfg.AdminGroups)+len(cfg.OperatorGroups)+len(cfg.ViewerGroups) == 0 && cfg.DefaultRole == "":
		return nil, errors.New("oidc: map at least one group to a role, or set a default role")
	}
	if cfg.DefaultRole != "" {
		if _, ok := ParseRole(string(cfg.DefaultRole)); !ok {
			return nil, fmt.Errorf("oidc: unknown default role %q", cfg.DefaultRole)
		}
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{oidc.ScopeOpenID, "profile", "email", "groups"}
	}
	if cfg.GroupsClaim == "" {
		cfg.GroupsClaim = "groups"
	}
	if cfg.DisplayName == "" {
		cfg.DisplayName = "single sign-on"
	}
	return &OIDC{cfg: cfg, pend: map[string]pending{}}, nil
}

func (o *OIDC) DisplayName() string { return o.cfg.DisplayName }

func (o *OIDC) ctx(ctx context.Context) context.Context {
	if o.cfg.HTTPClient != nil {
		return oidc.ClientContext(ctx, o.cfg.HTTPClient)
	}
	return ctx
}

// init discovers the provider lazily so the manager starts even if the IdP is briefly down.
func (o *OIDC) init(ctx context.Context) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.provider != nil {
		return nil
	}
	p, err := oidc.NewProvider(o.ctx(ctx), o.cfg.Issuer)
	if err != nil {
		return fmt.Errorf("oidc discovery: %w", err)
	}
	o.provider = p
	o.oauth = &oauth2.Config{
		ClientID: o.cfg.ClientID, ClientSecret: o.cfg.ClientSecret, Endpoint: p.Endpoint(),
		RedirectURL: o.cfg.RedirectURL, Scopes: o.cfg.Scopes,
	}
	return nil
}

func rnd() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// Start returns the IdP URL to send the browser to. State, nonce and PKCE verifier are kept
// server-side, single use, for ten minutes.
func (o *OIDC) Start(ctx context.Context) (string, error) {
	if err := o.init(ctx); err != nil {
		return "", err
	}
	state, nonce, verifier := rnd(), rnd(), oauth2.GenerateVerifier()
	o.mu.Lock()
	now := time.Now()
	for k, v := range o.pend {
		if now.Sub(v.created) > 10*time.Minute {
			delete(o.pend, k)
		}
	}
	if len(o.pend) > 5000 { // sign-in spam: refuse rather than grow without bound
		o.mu.Unlock()
		return "", errors.New("too many pending sign-ins")
	}
	o.pend[state] = pending{nonce: nonce, verifier: verifier, created: now}
	cfg := o.oauth
	o.mu.Unlock()
	return cfg.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)), nil
}

// Finish completes the code flow and returns the verified identity.
func (o *OIDC) Finish(ctx context.Context, state, code string) (ExternalIdentity, error) {
	o.mu.Lock()
	p, ok := o.pend[state]
	delete(o.pend, state) // single use, also on failure
	o.mu.Unlock()
	if !ok || time.Since(p.created) > 10*time.Minute || code == "" {
		return ExternalIdentity{}, ErrOIDCState
	}
	if err := o.init(ctx); err != nil {
		return ExternalIdentity{}, err
	}
	tok, err := o.oauth.Exchange(o.ctx(ctx), code, oauth2.VerifierOption(p.verifier))
	if err != nil {
		return ExternalIdentity{}, fmt.Errorf("oidc token exchange: %w", err)
	}
	raw, _ := tok.Extra("id_token").(string)
	if raw == "" {
		return ExternalIdentity{}, errors.New("oidc: no id_token in response")
	}
	idt, err := o.provider.Verifier(&oidc.Config{ClientID: o.cfg.ClientID}).Verify(o.ctx(ctx), raw)
	if err != nil {
		return ExternalIdentity{}, fmt.Errorf("oidc id_token: %w", err)
	}
	if idt.Nonce != p.nonce {
		return ExternalIdentity{}, errors.New("oidc: nonce mismatch")
	}
	var claims map[string]any
	if err := idt.Claims(&claims); err != nil {
		return ExternalIdentity{}, err
	}

	role, ok := o.roleFor(stringsClaim(claims[o.cfg.GroupsClaim]))
	if !ok {
		return ExternalIdentity{}, ErrNoRole
	}
	id := ExternalIdentity{Subject: o.cfg.Issuer + "#" + idt.Subject, Role: role}
	id.Username = firstValid(claims, "preferred_username", "email", "sub")
	id.DisplayName, _ = claims["name"].(string)
	if id.DisplayName == "" {
		id.DisplayName = id.Username
	}
	return id, nil
}

func (o *OIDC) roleFor(groups []string) (Role, bool) {
	has := func(want []string) bool {
		for _, g := range groups {
			for _, w := range want {
				if g == w {
					return true
				}
			}
		}
		return false
	}
	switch {
	case has(o.cfg.AdminGroups):
		return Admin, true
	case has(o.cfg.OperatorGroups):
		return Operator, true
	case has(o.cfg.ViewerGroups):
		return Viewer, true
	}
	return o.cfg.DefaultRole, o.cfg.DefaultRole != ""
}

// stringsClaim accepts a JSON array of strings or one comma/space separated string.
func stringsClaim(v any) []string {
	switch t := v.(type) {
	case []any:
		var out []string
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case string:
		return strings.FieldsFunc(t, func(r rune) bool { return r == ',' || r == ' ' })
	}
	return nil
}

func firstValid(claims map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, _ := claims[k].(string); s != "" && usernameRe.MatchString(s) {
			return s
		}
	}
	return ""
}

// ErrorRedirect builds a /login URL carrying a short message, for the callback to bounce to.
func ErrorRedirect(msg string) string {
	return "/#/login?error=" + url.QueryEscape(msg)
}
