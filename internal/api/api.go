// Package api exposes the REST interface: sign-in, per-registry authorization, audit, registries.
package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/rdeb/local-image-registry/internal/auth"
	"github.com/rdeb/local-image-registry/internal/runtime"
	"github.com/rdeb/local-image-registry/internal/service"
	"github.com/rdeb/local-image-registry/internal/store"
)

type Options struct {
	Auth  *auth.Service
	OIDC  *auth.OIDC // nil when SSO is not configured
	Store *store.Store

	DisableLocalLogin bool // SSO only
	TrustProxy        bool // take the client address from X-Forwarded-For
	Log               *slog.Logger
}

type API struct {
	svc *service.Service
	opt Options
	mux *http.ServeMux
	log *slog.Logger
}

const cookieName = "rui_session"

// public marks routes that need no session.
const public auth.Perm = -1

// Short names for the roles' minimum permission.
const (
	viewPerm    = auth.PermView
	operatePerm = auth.PermOperate
	adminPerm   = auth.PermAdmin
)

func New(svc *service.Service, opt Options) http.Handler {
	a := &API{svc: svc, opt: opt, mux: http.NewServeMux(), log: opt.Log}
	if a.log == nil {
		a.log = slog.Default()
	}
	a.routes()
	return a.mux
}

func (a *API) routes() {
	h := a.handle
	h("GET /api/healthz", public, "", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, map[string]string{"status": "ok"}) })

	// sign-in
	h("GET /api/auth/config", public, "", a.authConfig)
	h("POST /api/auth/login", public, "", a.login)
	h("GET /api/auth/oidc/login", public, "", a.oidcLogin)
	h("GET /api/auth/oidc/callback", public, "", a.oidcCallback)
	h("GET /api/auth/me", auth.PermNone, "", a.me)
	h("POST /api/auth/logout", auth.PermNone, "auth.logout", a.logout)
	h("POST /api/auth/password", auth.PermNone, "auth.password.change", a.changePassword)

	// registries
	h("GET /api/fleet", auth.PermView, "", a.fleet)
	h("GET /api/registries", auth.PermView, "", a.list)
	h("POST /api/registries", auth.PermAdmin, "registry.create", a.create)
	h("GET /api/registries/{name}", auth.PermView, "", a.get)
	h("DELETE /api/registries/{name}", auth.PermAdmin, "registry.delete", a.delete)
	h("POST /api/registries/{name}/start", auth.PermOperate, "registry.start", a.start)
	h("POST /api/registries/{name}/stop", auth.PermOperate, "registry.stop", a.stop)
	h("GET /api/registries/{name}/usage", auth.PermView, "", a.usage)
	h("GET /api/registries/{name}/repositories", auth.PermView, "", a.repos)
	h("GET /api/registries/{name}/tags", auth.PermView, "", a.tags)
	h("DELETE /api/registries/{name}/tags", auth.PermOperate, "registry.tag.delete", a.deleteTag)
	h("POST /api/registries/{name}/gc", auth.PermOperate, "registry.gc", a.gc)
	h("GET /api/registries/{name}/users", auth.PermView, "", a.users)
	h("PUT /api/registries/{name}/users/{user}", auth.PermOperate, "registry.user.set", a.setUser)
	h("DELETE /api/registries/{name}/users/{user}", auth.PermOperate, "registry.user.remove", a.removeUser)
	h("GET /api/registries/{name}/tls", auth.PermView, "", a.getTLS)
	h("PUT /api/registries/{name}/tls", auth.PermOperate, "registry.tls.set", a.setTLS)
	h("DELETE /api/registries/{name}/tls", auth.PermOperate, "registry.tls.remove", a.removeTLS)
	h("GET /api/registries/{name}/config", auth.PermOperate, "", a.getConfig) // env overrides may hold secrets
	h("PUT /api/registries/{name}/config", auth.PermOperate, "registry.config.update", a.setConfig)

	a.securityRoutes()
	a.imageRoutes()

	// administration
	h("GET /api/admin/accounts", auth.PermAdmin, "", a.accounts)
	h("POST /api/admin/accounts", auth.PermAdmin, "account.create", a.createAccount)
	h("PATCH /api/admin/accounts/{id}", auth.PermAdmin, "account.update", a.updateAccount)
	h("DELETE /api/admin/accounts/{id}", auth.PermAdmin, "account.delete", a.deleteAccount)
	h("POST /api/admin/accounts/{id}/password", auth.PermAdmin, "account.password.reset", a.resetAccountPassword)
	h("GET /api/admin/audit", auth.PermAdmin, "", a.auditLog)
}

// ---- registry handlers ----

func (a *API) list(w http.ResponseWriter, r *http.Request) {
	p := principalOf(r)
	all, err := a.svc.List(r.Context())
	out := all[:0:0]
	for _, v := range all {
		if p.CanSee(v.Name) {
			out = append(out, v)
		}
	}
	respond(w, 200, out, err)
}

func (a *API) fleet(w http.ResponseWriter, r *http.Request) {
	p := principalOf(r)
	sum, items, err := a.svc.Fleet(r.Context(), p.CanSee)
	respond(w, 200, map[string]any{"summary": sum, "registries": items}, err)
}

func (a *API) create(w http.ResponseWriter, r *http.Request) {
	var in service.CreateInput
	if !decode(w, r, &in) {
		return
	}
	setAudit(r, in.Name, nil)
	v, err := a.svc.Create(r.Context(), in)
	respond(w, 201, v, err)
}

func (a *API) get(w http.ResponseWriter, r *http.Request) {
	v, err := a.svc.Get(r.Context(), r.PathValue("name"))
	respond(w, 200, v, err)
}

func (a *API) start(w http.ResponseWriter, r *http.Request) {
	v, err := a.svc.Start(r.Context(), r.PathValue("name"))
	respond(w, 200, v, err)
}

func (a *API) stop(w http.ResponseWriter, r *http.Request) {
	v, err := a.svc.Stop(r.Context(), r.PathValue("name"))
	respond(w, 200, v, err)
}

// DELETE removes the instance; ?keepData=true retains the storage volume.
func (a *API) delete(w http.ResponseWriter, r *http.Request) {
	keep := r.URL.Query().Get("keepData") == "true"
	setAudit(r, "", map[string]string{"keepData": boolStr(keep)})
	if err := a.svc.Delete(r.Context(), r.PathValue("name"), !keep); err != nil {
		respond(w, 0, nil, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) repos(w http.ResponseWriter, r *http.Request) {
	v, err := a.svc.Repositories(r.Context(), r.PathValue("name"))
	respond(w, 200, v, err)
}

// GET ...?repo=team/app
func (a *API) tags(w http.ResponseWriter, r *http.Request) {
	v, err := a.svc.Tags(r.Context(), r.PathValue("name"), r.URL.Query().Get("repo"))
	respond(w, 200, v, err)
}

// DELETE ...?repo=team/app&tag=v1 deletes the manifest behind the tag.
func (a *API) deleteTag(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	setAudit(r, "", map[string]string{"repo": q.Get("repo"), "tag": q.Get("tag")})
	d, err := a.svc.DeleteTag(r.Context(), r.PathValue("name"), q.Get("repo"), q.Get("tag"))
	respond(w, 200, map[string]string{"deletedDigest": d}, err)
}

func (a *API) gc(w http.ResponseWriter, r *http.Request) {
	v, err := a.svc.GC(r.Context(), r.PathValue("name"))
	if err == nil {
		setAudit(r, "", map[string]string{"freedBytes": itoa(v.BytesBefore - v.BytesAfter)})
	}
	respond(w, 200, v, err)
}

func (a *API) usage(w http.ResponseWriter, r *http.Request) {
	n, err := a.svc.Usage(r.Context(), r.PathValue("name"))
	respond(w, 200, map[string]int64{"usedBytes": n}, err)
}

func (a *API) users(w http.ResponseWriter, r *http.Request) {
	v, err := a.svc.Users(r.Context(), r.PathValue("name"))
	respond(w, 200, map[string][]string{"users": v}, err)
}

// PUT body {"password": "..."} adds the user or changes their password.
func (a *API) setUser(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Password string `json:"password"`
	}
	if !decode(w, r, &in) {
		return
	}
	setAudit(r, "", map[string]string{"user": r.PathValue("user")})
	err := a.svc.SetUser(r.Context(), r.PathValue("name"), r.PathValue("user"), in.Password)
	respond(w, 200, map[string]string{"user": r.PathValue("user")}, err)
}

func (a *API) removeUser(w http.ResponseWriter, r *http.Request) {
	setAudit(r, "", map[string]string{"user": r.PathValue("user")})
	if err := a.svc.RemoveUser(r.Context(), r.PathValue("name"), r.PathValue("user")); err != nil {
		respond(w, 0, nil, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) getTLS(w http.ResponseWriter, r *http.Request) {
	v, err := a.svc.TLS(r.Context(), r.PathValue("name"))
	respond(w, 200, v, err)
}

func (a *API) setTLS(w http.ResponseWriter, r *http.Request) {
	var in service.TLSInput
	if !decode(w, r, &in) {
		return
	}
	setAudit(r, "", map[string]string{"mode": map[bool]string{true: "generated", false: "uploaded"}[in.Generate]})
	v, err := a.svc.SetTLS(r.Context(), r.PathValue("name"), in)
	respond(w, 200, v, err)
}

func (a *API) removeTLS(w http.ResponseWriter, r *http.Request) {
	if err := a.svc.RemoveTLS(r.Context(), r.PathValue("name")); err != nil {
		respond(w, 0, nil, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) getConfig(w http.ResponseWriter, r *http.Request) {
	v, err := a.svc.Config(r.Context(), r.PathValue("name"))
	respond(w, 200, v, err)
}

func (a *API) setConfig(w http.ResponseWriter, r *http.Request) {
	var in service.ConfigInput
	if !decode(w, r, &in) {
		return
	}
	keys := make([]string, 0, len(in.Env))
	for k := range in.Env {
		keys = append(keys, k) // names only: values may be secrets
	}
	setAudit(r, "", map[string]string{"customConfig": boolStr(in.Config != ""), "envKeys": strings.Join(keys, ",")})
	v, err := a.svc.SetConfig(r.Context(), r.PathValue("name"), in)
	respond(w, 200, v, err)
}

// ---- helpers ----

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeJSON(w, 400, map[string]string{"error": "bad json: " + err.Error()})
		return false
	}
	return true
}

func respond(w http.ResponseWriter, ok int, v any, err error) {
	if err != nil {
		code, msg := 500, err.Error()
		switch {
		case errors.Is(err, service.ErrNotFound), errors.Is(err, runtime.ErrNotFound), errors.Is(err, auth.ErrNotFound):
			code = 404
		case errors.Is(err, service.ErrExists), errors.Is(err, service.ErrNotRunning), errors.Is(err, auth.ErrExists), errors.Is(err, auth.ErrLastAdmin), errors.Is(err, auth.ErrSelf),
			errors.Is(err, service.ErrNoSigningKey), errors.Is(err, service.ErrNotReady), errors.Is(err, service.ErrTransferBusy), errors.Is(err, service.ErrNothingToFix):
			code = 409
		case errors.Is(err, service.ErrInvalid), errors.Is(err, auth.ErrInvalid):
			code = 400
		case errors.Is(err, runtime.ErrImage):
			code = 502 // the registry or tool image could not be downloaded: the message says which and why
		case errors.Is(err, service.ErrNoPorts):
			code = 507
		case errors.Is(err, runtime.ErrUnsupported), errors.Is(err, service.ErrSecurityDisabled):
			code = 501
		}
		if code == 500 {
			msg = "internal error" // never leak driver/DB details to the client; they are in the server log
			slog.Error("request failed", "err", err)
		}
		writeJSON(w, code, map[string]string{"error": msg})
		return
	}
	writeJSON(w, ok, v)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
