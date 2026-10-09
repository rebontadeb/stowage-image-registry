package api

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/rdeb/local-image-registry/internal/auth"
	"github.com/rdeb/local-image-registry/internal/store"
)

type meResponse struct {
	auth.Principal
	Registries []string `json:"registries"`
}

func (a *API) me(w http.ResponseWriter, r *http.Request) {
	p := principalOf(r)
	regs := make([]string, 0, len(p.Registries))
	for k := range p.Registries {
		regs = append(regs, k)
	}
	writeJSON(w, 200, meResponse{Principal: p, Registries: regs})
}

func (a *API) authConfig(w http.ResponseWriter, _ *http.Request) {
	out := map[string]any{"localLogin": !a.opt.DisableLocalLogin, "oidc": a.opt.OIDC != nil, "security": a.svc.SecurityEnabled()}
	if a.opt.OIDC != nil {
		out["oidcName"] = a.opt.OIDC.DisplayName()
	}
	writeJSON(w, 200, out)
}

func (a *API) login(w http.ResponseWriter, r *http.Request) {
	var in struct{ Username, Password string }
	if !decode(w, r, &in) {
		return
	}
	entry := store.AuditEntry{Actor: in.Username, Action: "auth.login", Detail: map[string]string{"method": "local"}, IP: a.clientIP(r)}
	if a.opt.DisableLocalLogin {
		entry.Outcome = "denied"
		a.auditRaw(entry)
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "local sign-in is disabled; use single sign-on", "code": "forbidden"})
		return
	}
	token, p, err := a.opt.Auth.Login(in.Username, in.Password, entry.IP)
	if err != nil {
		entry.Outcome = "denied"
		var locked *auth.LockedError
		if errors.As(err, &locked) {
			entry.Detail["reason"] = "locked"
			a.auditRaw(entry)
			w.Header().Set("Retry-After", strconv.Itoa(int(locked.RetryAfter.Seconds())+1))
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": locked.Error(), "code": "locked"})
			return
		}
		entry.Detail["reason"] = "bad credentials"
		a.auditRaw(entry)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": auth.ErrInvalidCredentials.Error(), "code": "invalid_credentials"})
		return
	}
	entry.Actor, entry.ActorRole, entry.Outcome = p.Username, string(p.Role), "ok"
	a.auditRaw(entry)
	a.setSessionCookie(w, r, token)
	a.me(w, r.WithContext(withPrincipal(r, p)))
}

func (a *API) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil {
		a.opt.Auth.Logout(c.Value)
	}
	clearSessionCookie(w, r)
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) changePassword(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if !decode(w, r, &in) {
		return
	}
	c, _ := r.Cookie(cookieName)
	err := a.opt.Auth.ChangePassword(principalOf(r), c.Value, in.Current, in.New)
	if errors.Is(err, auth.ErrInvalidCredentials) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "current password is incorrect"})
		return
	}
	respond(w, 200, map[string]bool{"ok": true}, err)
}

// ---- OIDC ----

func (a *API) oidcLogin(w http.ResponseWriter, r *http.Request) {
	if a.opt.OIDC == nil {
		http.NotFound(w, r)
		return
	}
	u, err := a.opt.OIDC.Start(r.Context())
	if err != nil {
		a.log.Error("oidc start", "err", err)
		http.Redirect(w, r, auth.ErrorRedirect("Single sign-on is unavailable right now."), http.StatusFound)
		return
	}
	http.Redirect(w, r, u, http.StatusFound)
}

func (a *API) oidcCallback(w http.ResponseWriter, r *http.Request) {
	if a.opt.OIDC == nil {
		http.NotFound(w, r)
		return
	}
	entry := store.AuditEntry{Action: "auth.login", Detail: map[string]string{"method": "oidc"}, IP: a.clientIP(r)}
	fail := func(reason, userMsg string) {
		entry.Outcome, entry.Detail["reason"] = "denied", reason
		if entry.Actor == "" {
			entry.Actor = "(unknown)"
		}
		a.auditRaw(entry)
		http.Redirect(w, r, auth.ErrorRedirect(userMsg), http.StatusFound)
	}
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		fail("idp error: "+e, "Sign-in was cancelled or refused by the identity provider.")
		return
	}
	id, err := a.opt.OIDC.Finish(r.Context(), q.Get("state"), q.Get("code"))
	if err != nil {
		a.log.Warn("oidc callback", "err", err)
		msg := "Sign-in failed. Please try again."
		if errors.Is(err, auth.ErrNoRole) {
			msg = err.Error()
		}
		fail(err.Error(), msg)
		return
	}
	entry.Actor = id.Username
	token, p, err := a.opt.Auth.LoginExternal(id)
	if err != nil {
		msg := "Sign-in failed. Please contact an administrator."
		if errors.Is(err, auth.ErrDisabled) {
			msg = "Your account is disabled."
		}
		fail(err.Error(), msg)
		return
	}
	entry.Actor, entry.ActorRole, entry.Outcome = p.Username, string(p.Role), "ok"
	a.auditRaw(entry)
	a.setSessionCookie(w, r, token)
	http.Redirect(w, r, "/", http.StatusFound)
}

// ---- administration ----

func (a *API) accounts(w http.ResponseWriter, _ *http.Request) {
	v, err := a.opt.Auth.Accounts()
	respond(w, 200, v, err)
}

type accountInput struct {
	Username      string   `json:"username"`
	DisplayName   string   `json:"displayName"`
	Password      string   `json:"password"`
	Role          string   `json:"role"`
	AllRegistries bool     `json:"allRegistries"`
	Registries    []string `json:"registries"`
	MustChange    bool     `json:"mustChangePassword"`
}

func (a *API) createAccount(w http.ResponseWriter, r *http.Request) {
	var in accountInput
	if !decode(w, r, &in) {
		return
	}
	setAudit(r, in.Username, map[string]string{"role": in.Role})
	v, err := a.opt.Auth.CreateLocal(auth.NewAccount{
		Username: in.Username, DisplayName: in.DisplayName, Password: in.Password, Role: auth.Role(in.Role),
		AllRegistries: in.AllRegistries, Registries: in.Registries, MustChange: in.MustChange,
	})
	respond(w, 201, v, err)
}

func (a *API) accountID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return 0, false
	}
	if acc, err := a.opt.Auth.Account(id); err == nil {
		setAudit(r, acc.Username, nil)
	}
	return id, true
}

func (a *API) updateAccount(w http.ResponseWriter, r *http.Request) {
	id, ok := a.accountID(w, r)
	if !ok {
		return
	}
	var in struct {
		DisplayName   *string   `json:"displayName"`
		Role          *string   `json:"role"`
		Disabled      *bool     `json:"disabled"`
		AllRegistries *bool     `json:"allRegistries"`
		Registries    *[]string `json:"registries"`
	}
	if !decode(w, r, &in) {
		return
	}
	patch := auth.Patch{DisplayName: in.DisplayName, Disabled: in.Disabled, AllRegistries: in.AllRegistries, Registries: in.Registries}
	d := map[string]string{}
	if in.Role != nil {
		role := auth.Role(*in.Role)
		patch.Role = &role
		d["role"] = *in.Role
	}
	if in.Disabled != nil {
		d["disabled"] = boolStr(*in.Disabled)
	}
	if in.Registries != nil {
		d["registries"] = strings.Join(*in.Registries, ",")
	}
	if in.AllRegistries != nil {
		d["allRegistries"] = boolStr(*in.AllRegistries)
	}
	setAudit(r, "", d)
	v, err := a.opt.Auth.Update(principalOf(r), id, patch)
	respond(w, 200, v, err)
}

func (a *API) deleteAccount(w http.ResponseWriter, r *http.Request) {
	id, ok := a.accountID(w, r)
	if !ok {
		return
	}
	if err := a.opt.Auth.Delete(principalOf(r), id); err != nil {
		respond(w, 0, nil, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) resetAccountPassword(w http.ResponseWriter, r *http.Request) {
	id, ok := a.accountID(w, r)
	if !ok {
		return
	}
	var in struct {
		Password   string `json:"password"`
		MustChange bool   `json:"mustChangePassword"`
	}
	if !decode(w, r, &in) {
		return
	}
	err := a.opt.Auth.ResetPassword(id, in.Password, in.MustChange)
	respond(w, 200, map[string]bool{"ok": true}, err)
}

// ---- audit ----

func (a *API) auditLog(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.AuditFilter{Actor: q.Get("actor"), Action: q.Get("action"), Target: q.Get("target"), Outcome: q.Get("outcome")}
	f.BeforeID, _ = strconv.ParseInt(q.Get("before"), 10, 64)
	f.Limit, _ = strconv.Atoi(q.Get("limit"))
	for k, dst := range map[string]*time.Time{"since": &f.Since, "until": &f.Until} {
		if v := q.Get(k); v != "" {
			t, err := time.Parse(time.RFC3339, v)
			if err != nil {
				writeJSON(w, 400, map[string]string{"error": k + " must be RFC 3339, e.g. 2026-01-31T00:00:00Z"})
				return
			}
			*dst = t
		}
	}
	if q.Get("format") == "csv" {
		a.auditCSV(w, f)
		return
	}
	entries, err := a.opt.Store.QueryAudit(f)
	next := int64(0)
	if err == nil && len(entries) > 0 && (f.Limit <= 0 && len(entries) == 100 || f.Limit > 0 && len(entries) == f.Limit) {
		next = entries[len(entries)-1].ID // more may follow: pass as ?before=
	}
	respond(w, 200, map[string]any{"entries": entries, "next": next}, err)
}
