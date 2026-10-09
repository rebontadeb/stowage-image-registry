package api

import (
	"errors"
	"net/http"
	"path/filepath"
	"strconv"

	"github.com/rdeb/local-image-registry/internal/service"
)

func (a *API) imageRoutes() {
	h := a.handle
	h("POST /api/registries/{name}/images/import", operatePerm, "registry.image.import", a.importImage)
	h("POST /api/registries/{name}/images/upload", operatePerm, "registry.image.upload", a.uploadImage)
	h("GET /api/registries/{name}/images/transfers", operatePerm, "", a.transfers)
	h("POST /api/registries/{name}/images/fix", operatePerm, "registry.image.fix", a.fixImage)
	h("POST /api/registries/{name}/images/rebase", operatePerm, "registry.image.rebase", a.rebaseImage)
	h("POST /api/registries/{name}/images/rebase-check", operatePerm, "", a.rebaseCheck)
	h("GET /api/registries/{name}/images/fix-plan", operatePerm, "", a.fixPlan)
	h("GET /api/registries/{name}/repository-summaries", viewPerm, "", a.repoSummaries)
	h("DELETE /api/registries/{name}/repositories", operatePerm, "registry.repo.delete", a.deleteRepo)
}

func (a *API) importImage(w http.ResponseWriter, r *http.Request) {
	var in importBody
	if !decode(w, r, &in) {
		return
	}
	// Credentials are deliberately absent from the audit detail.
	setAudit(r, "", map[string]string{"source": in.Source, "repo": in.Repo, "tag": in.Tag,
		"allPlatforms": boolStr(in.AllPlatforms), "overwrite": boolStr(in.Overwrite), "privateSource": boolStr(in.Username != "")})
	v, err := a.svc.ImportImage(r.Context(), r.PathValue("name"), in.ImportInput, principalOf(r).Username)
	respond(w, http.StatusAccepted, v, err)
}

// POST /images/upload?repo=team/app&tag=1.0&filename=app.tar[&overwrite=true][&scan=true]; body = the archive.
func (a *API) uploadImage(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	repo, tag, file := q.Get("repo"), q.Get("tag"), q.Get("filename")
	setAudit(r, "", map[string]string{"repo": repo, "tag": tag, "file": filepath.Base(file)})
	body := http.MaxBytesReader(w, r.Body, a.svc.ImportLimit()+(1<<20))
	v, err := a.svc.UploadImage(r.Context(), r.PathValue("name"), repo, tag, file, body,
		q.Get("overwrite") == "true", q.Get("scan") == "true", principalOf(r).Username)
	var tooBig *http.MaxBytesError
	if errors.As(err, &tooBig) {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "the file is larger than the allowed image size"})
		return
	}
	respond(w, http.StatusAccepted, v, err)
}

func (a *API) repoSummaries(w http.ResponseWriter, r *http.Request) {
	v, err := a.svc.RepoSummaries(r.Context(), r.PathValue("name"))
	respond(w, 200, v, err)
}

// DELETE /repositories?repo=team/app removes every image in the repository.
func (a *API) deleteRepo(w http.ResponseWriter, r *http.Request) {
	repo := r.URL.Query().Get("repo")
	setAudit(r, "", map[string]string{"repo": repo})
	res, err := a.svc.DeleteRepository(r.Context(), r.PathValue("name"), repo)
	if err == nil || res.Manifests > 0 {
		setAudit(r, "", map[string]string{"tags": strconv.Itoa(res.Tags), "manifests": strconv.Itoa(res.Manifests)})
	}
	respond(w, http.StatusOK, res, err)
}

func (a *API) transfers(w http.ResponseWriter, r *http.Request) {
	v, err := a.svc.Transfers(r.PathValue("name"))
	respond(w, 200, v, err)
}

// importBody is the request body: the service's input, decoded strictly.
type importBody struct {
	service.ImportInput
}

// POST /images/fix {repo, ref, tag?}: patch the fixable OS packages into a new tag.
func (a *API) fixImage(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Repo string `json:"repo"`
		Ref  string `json:"ref"`
		Tag  string `json:"tag"`
	}
	if !decode(w, r, &in) {
		return
	}
	setAudit(r, "", map[string]string{"repo": in.Repo, "ref": in.Ref, "tag": in.Tag})
	v, err := a.svc.FixImage(r.Context(), r.PathValue("name"), in.Repo, in.Ref, in.Tag, principalOf(r).Username)
	respond(w, http.StatusAccepted, v, err)
}

// GET /images/fix-plan?repo=&ref=[&tag=]: what a fix would upgrade, and the tag it would create.
func (a *API) fixPlan(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	v, err := a.svc.PlanFix(r.Context(), r.PathValue("name"), q.Get("repo"), q.Get("ref"), q.Get("tag"))
	respond(w, 200, v, err)
}

// POST /images/rebase: move an image onto a newer base image, as a new tag.
func (a *API) rebaseImage(w http.ResponseWriter, r *http.Request) {
	var in service.RebaseInput
	if !decode(w, r, &in) {
		return
	}
	// Credentials are deliberately absent from the audit detail.
	setAudit(r, "", map[string]string{"repo": in.Repo, "ref": in.Ref, "oldBase": in.OldBase, "newBase": in.NewBase, "tag": in.Tag, "privateBase": boolStr(in.Username != "")})
	v, err := a.svc.RebaseImage(r.Context(), r.PathValue("name"), in, principalOf(r).Username)
	respond(w, http.StatusAccepted, v, err)
}

// POST /images/rebase-check {repo, ref, oldBase, ...}: is the image built on that base? Changes nothing.
func (a *API) rebaseCheck(w http.ResponseWriter, r *http.Request) {
	var in service.RebaseInput
	if !decode(w, r, &in) {
		return
	}
	v, err := a.svc.CheckRebaseBase(r.Context(), r.PathValue("name"), in.Repo, in.Ref, in.OldBase, in)
	respond(w, http.StatusOK, v, err)
}
