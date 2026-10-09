package api

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/rdeb/local-image-registry/internal/auth"
	"github.com/rdeb/local-image-registry/internal/store"
)

type ctxKey int

const (
	keyPrincipal ctxKey = iota
	keyAudit
)

// auditInfo lets a handler enrich the audit entry the middleware writes for it.
type auditInfo struct {
	target string
	detail map[string]string
}

func setAudit(r *http.Request, target string, detail map[string]string) {
	info, _ := r.Context().Value(keyAudit).(*auditInfo)
	if info == nil {
		return
	}
	if target != "" {
		info.target = target
	}
	for k, v := range detail {
		if info.detail == nil {
			info.detail = map[string]string{}
		}
		info.detail[k] = v
	}
}

func principalOf(r *http.Request) auth.Principal {
	p, _ := r.Context().Value(keyPrincipal).(auth.Principal)
	return p
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(c int) {
	if w.status == 0 {
		w.status = c
	}
	w.ResponseWriter.WriteHeader(c)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

// Routes a user may call while their password is flagged for change.
var allowedWhileMustChange = map[string]bool{
	"GET /api/auth/me": true, "POST /api/auth/logout": true, "POST /api/auth/password": true,
}

// handle registers a route behind authentication, role and registry-scope checks, and audits
// state-changing calls (including denied ones) under `action`.
func (a *API) handle(pattern string, perm auth.Perm, action string, h http.HandlerFunc) {
	scoped := strings.Contains(pattern, "{name}")
	unsafe := !strings.HasPrefix(pattern, "GET ") && !strings.HasPrefix(pattern, "HEAD ")

	a.mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		sw := &statusWriter{ResponseWriter: w}
		info := &auditInfo{target: r.PathValue("name")}
		ctx := context.WithValue(r.Context(), keyAudit, info)

		if unsafe && !sameOrigin(r) {
			writeJSON(sw, http.StatusForbidden, map[string]string{"error": "cross-origin request refused", "code": "forbidden"})
			return
		}

		var p auth.Principal
		if perm != public {
			c, _ := r.Cookie(cookieName)
			tok := ""
			if c != nil {
				tok = c.Value
			}
			var err error
			if p, err = a.opt.Auth.Authenticate(tok); err != nil {
				writeJSON(sw, http.StatusUnauthorized, map[string]string{"error": "sign in required", "code": "unauthenticated"})
				return
			}
			ctx = context.WithValue(ctx, keyPrincipal, p)

			deny := func(code int, msg, c string) {
				if unsafe && action != "" {
					a.audit(r, p, action, info, "denied")
				}
				writeJSON(sw, code, map[string]string{"error": msg, "code": c})
			}
			switch {
			case p.MustChange && !allowedWhileMustChange[pattern]:
				deny(http.StatusForbidden, "you must change your password first", "password_change_required")
				return
			case !p.Role.Allows(perm):
				deny(http.StatusForbidden, "your role does not allow this", "forbidden")
				return
			case scoped && !p.CanSee(r.PathValue("name")):
				deny(http.StatusNotFound, "not found", "not_found") // do not reveal that it exists
				return
			}
		}

		h(sw, r.WithContext(ctx))

		if perm != public && unsafe && action != "" {
			outcome := "ok"
			if sw.status >= 400 {
				outcome = "error"
			}
			a.audit(r, p, action, info, outcome)
		}
	})
}

func (a *API) audit(r *http.Request, p auth.Principal, action string, info *auditInfo, outcome string) {
	a.auditRaw(store.AuditEntry{
		Actor: p.Username, ActorRole: string(p.Role), Action: action, Target: info.target,
		Detail: info.detail, Outcome: outcome, IP: a.clientIP(r),
	})
}

func (a *API) auditRaw(e store.AuditEntry) {
	if err := a.opt.Store.AddAudit(e); err != nil {
		a.log.Error("audit write failed", "err", err, "action", e.Action, "actor", e.Actor)
	}
}

// sameOrigin rejects browser requests from another origin. Requests without an Origin header
// (curl, scripts) pass: they carry no ambient credentials a third-party page could ride on.
func sameOrigin(r *http.Request) bool {
	o := r.Header.Get("Origin")
	if o == "" {
		return true
	}
	u, err := url.Parse(o)
	return err == nil && u.Host == r.Host
}

func (a *API) clientIP(r *http.Request) string {
	if a.opt.TrustProxy {
		if xf := r.Header.Get("X-Forwarded-For"); xf != "" {
			return strings.TrimSpace(strings.Split(xf, ",")[0])
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (a *API) setSessionCookie(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: token, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode,
		Secure: isHTTPS(r), MaxAge: int(a.opt.Auth.MaxLifetime.Seconds()),
	})
}

func clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: isHTTPS(r), MaxAge: -1})
}

func isHTTPS(r *http.Request) bool {
	return r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
}

// Secure adds hardening headers to every response (UI and API).
func Secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		if isHTTPS(r) {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

func withPrincipal(r *http.Request, p auth.Principal) context.Context {
	return context.WithValue(r.Context(), keyPrincipal, p)
}
