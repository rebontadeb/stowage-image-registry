// Package authtest provides a minimal OpenID Connect provider for tests: discovery, JWKS and a
// token endpoint that enforces PKCE. It is test support only and never linked into the server.
package authtest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

type IdP struct {
	Server *httptest.Server
	key    *rsa.PrivateKey
	codes  map[string]grant

	// Knobs for negative tests.
	NonceOverride string
	Audience      string // default "mgr"
}

type grant struct {
	nonce, challenge string
	claims           map[string]any
}

func New(t *testing.T) *IdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &IdP{key: key, codes: map[string]grant{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": f.Server.URL, "authorization_endpoint": f.Server.URL + "/authorize", "token_endpoint": f.Server.URL + "/token",
			"jwks_uri": f.Server.URL + "/jwks", "id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		g, ok := f.codes[r.Form.Get("code")]
		delete(f.codes, r.Form.Get("code")) // codes are single use
		sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		if !ok || base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge {
			http.Error(w, `{"error":"invalid_grant"}`, 400)
			return
		}
		nonce := g.nonce
		if f.NonceOverride != "" {
			nonce = f.NonceOverride
		}
		aud := f.Audience
		if aud == "" {
			aud = "mgr"
		}
		claims := map[string]any{"iss": f.Server.URL, "aud": aud, "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(), "nonce": nonce}
		for k, v := range g.claims {
			claims[k] = v
		}
		sig, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: key, KeyID: "k1"}}, (&jose.SignerOptions{}).WithType("JWT"))
		idt, _ := jwt.Signed(sig).Claims(claims).Serialize()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "id_token": idt})
	})
	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Server.Close)
	return f
}

func (f *IdP) URL() string { return f.Server.URL }

// Authorize plays the browser: it reads the authorization URL the manager produced, "signs in" as
// the user described by claims, and returns the state and code the IdP would redirect back with.
func (f *IdP) Authorize(t *testing.T, authURL string, claims map[string]any) (state, code string) {
	t.Helper()
	u, err := url.Parse(authURL)
	if err != nil || !strings.HasPrefix(authURL, f.Server.URL+"/authorize") {
		t.Fatalf("bad authorization URL %q: %v", authURL, err)
	}
	q := u.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" || q.Get("nonce") == "" || q.Get("state") == "" {
		t.Fatalf("authorization request lacks PKCE/nonce/state: %v", q)
	}
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	code = "code-" + base64.RawURLEncoding.EncodeToString(b)
	f.codes[code] = grant{nonce: q.Get("nonce"), challenge: q.Get("code_challenge"), claims: claims}
	return q.Get("state"), code
}
