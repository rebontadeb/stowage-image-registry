package api

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

func (a *API) securityRoutes() {
	h := a.handle
	h("GET /api/registries/{name}/scans", viewPerm, "", a.scans)
	h("POST /api/registries/{name}/scans", operatePerm, "registry.scan.run", a.startScan)
	h("GET /api/registries/{name}/scans/result", viewPerm, "", a.scanResult)
	h("GET /api/registries/{name}/scans/download", viewPerm, "", a.scanDownload)
	h("POST /api/registries/{name}/sign", operatePerm, "registry.sign", a.sign)
	h("GET /api/registries/{name}/signing", viewPerm, "", a.signingInfo)
	h("POST /api/registries/{name}/signing-key", adminPerm, "registry.signingkey.create", a.createSigningKey)
	h("DELETE /api/registries/{name}/signing-key", adminPerm, "registry.signingkey.delete", a.deleteSigningKey)
	h("POST /api/registries/{name}/trust-keys", operatePerm, "registry.trustkey.add", a.addTrustKey)
	h("DELETE /api/registries/{name}/trust-keys/{id}", operatePerm, "registry.trustkey.remove", a.removeTrustKey)

	h("GET /api/admin/security", adminPerm, "", a.securityStatus)
	h("POST /api/admin/security/content", adminPerm, "security.content.add", a.addContentURL)
	h("PUT /api/admin/security/content/{content}", adminPerm, "security.content.add", a.uploadContent)
	h("DELETE /api/admin/security/content/{content}", adminPerm, "security.content.delete", a.deleteContent)
}

func (a *API) scans(w http.ResponseWriter, r *http.Request) {
	v, err := a.svc.ScanStatuses(r.PathValue("name"), r.URL.Query().Get("repo"))
	respond(w, 200, v, err)
}

func (a *API) startScan(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Repo  string   `json:"repo"`
		Ref   string   `json:"ref"` // tag or digest
		Kinds []string `json:"kinds"`
	}
	if !decode(w, r, &in) {
		return
	}
	setAudit(r, "", map[string]string{"repo": in.Repo, "ref": in.Ref, "kinds": strings.Join(in.Kinds, ",")})
	digest, queued, err := a.svc.StartScans(r.Context(), r.PathValue("name"), in.Repo, in.Ref, in.Kinds, principalOf(r).Username)
	respond(w, 202, map[string]any{"digest": digest, "queued": queued}, err)
}

func (a *API) scanResult(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	v, err := a.svc.ScanDetail(r.PathValue("name"), q.Get("repo"), q.Get("digest"), q.Get("kind"))
	respond(w, 200, v, err)
}

func (a *API) scanDownload(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	data, name, ct, err := a.svc.Download(r.PathValue("name"), q.Get("repo"), q.Get("digest"), q.Get("what"))
	if err != nil {
		respond(w, 0, nil, err)
		return
	}
	w.Header().Set("Content-Type", ct)
	// Scanner reports are untrusted HTML/JSON: only ever offer them as a download.
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name))
	w.Header().Set("Content-Security-Policy", "sandbox")
	_, _ = w.Write(data)
}

func (a *API) sign(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Repo string `json:"repo"`
		Ref  string `json:"ref"`
	}
	if !decode(w, r, &in) {
		return
	}
	setAudit(r, "", map[string]string{"repo": in.Repo, "ref": in.Ref})
	d, err := a.svc.Sign(r.Context(), r.PathValue("name"), in.Repo, in.Ref, principalOf(r).Username)
	respond(w, 200, map[string]string{"digest": d}, err)
}

func (a *API) signingInfo(w http.ResponseWriter, r *http.Request) {
	v, err := a.svc.SigningInfo(r.PathValue("name"))
	respond(w, 200, v, err)
}

func (a *API) createSigningKey(w http.ResponseWriter, r *http.Request) {
	v, err := a.svc.CreateSigningKey(r.PathValue("name"))
	if err == nil {
		setAudit(r, "", map[string]string{"fingerprint": v.Fingerprint})
	}
	respond(w, 201, v, err)
}

func (a *API) deleteSigningKey(w http.ResponseWriter, r *http.Request) {
	if err := a.svc.DeleteSigningKey(r.PathValue("name")); err != nil {
		respond(w, 0, nil, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) addTrustKey(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Label     string `json:"label"`
		PublicKey string `json:"publicKey"`
	}
	if !decode(w, r, &in) {
		return
	}
	setAudit(r, "", map[string]string{"label": in.Label})
	v, err := a.svc.AddTrustKey(r.PathValue("name"), in.Label, in.PublicKey)
	if err == nil {
		setAudit(r, "", map[string]string{"fingerprint": v.Fingerprint})
	}
	respond(w, 201, v, err)
}

func (a *API) removeTrustKey(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	setAudit(r, "", map[string]string{"keyId": r.PathValue("id")})
	if err := a.svc.RemoveTrustKey(r.PathValue("name"), id); err != nil {
		respond(w, 0, nil, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) securityStatus(w http.ResponseWriter, _ *http.Request) {
	v, err := a.svc.SecurityStatus()
	respond(w, 200, v, err)
}

func (a *API) addContentURL(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name string `json:"name"`
		URL  string `json:"url"`
	}
	if !decode(w, r, &in) {
		return
	}
	setAudit(r, in.Name, map[string]string{"source": in.URL})
	// The service applies its own download timeout.
	v, err := a.svc.AddContentURL(r.Context(), in.Name, in.URL, principalOf(r).Username)
	respond(w, 201, v, err)
}

// PUT /api/admin/security/content/{content}?filename=rhel-9.oval.xml.bz2, body = the file.
func (a *API) uploadContent(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("content")
	setAudit(r, name, map[string]string{"source": "upload"})
	body := http.MaxBytesReader(w, r.Body, 301<<20)
	defer io.Copy(io.Discard, io.LimitReader(body, 1<<20))
	v, err := a.svc.AddContentUpload(name, r.URL.Query().Get("filename"), body, "upload", principalOf(r).Username)
	respond(w, 201, v, err)
}

func (a *API) deleteContent(w http.ResponseWriter, r *http.Request) {
	setAudit(r, r.PathValue("content"), nil)
	if err := a.svc.DeleteContent(r.PathValue("content")); err != nil {
		respond(w, 0, nil, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
