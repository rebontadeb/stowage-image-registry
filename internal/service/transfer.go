package service

import (
	"compress/gzip"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	gort "runtime"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"

	"github.com/rdeb/local-image-registry/internal/regclient"
	"github.com/rdeb/local-image-registry/internal/store"
)

// DefaultImportLimit caps one image's size (config + layers) for imports and uploads.
const DefaultImportLimit = 8 << 30

const maxConcurrentTransfers = 2

var (
	tagRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$`)

	// ErrTransferBusy means the same destination is already being written.
	ErrTransferBusy = errors.New("a transfer to this repository and tag is already running")
)

const (
	TransferQueued  = "queued"
	TransferRunning = "running"
	TransferDone    = "done"
	TransferFailed  = "failed"
)

// TransferView describes one add-image job. Credentials are never part of it.
type TransferView struct {
	ID       string    `json:"id"`
	Kind     string    `json:"kind"` // "import" | "upload"
	Registry string    `json:"registry"`
	Repo     string    `json:"repo"`
	Tag      string    `json:"tag"`
	Source   string    `json:"source,omitempty"` // import: the source reference; upload: the file name
	Status   string    `json:"status"`
	Error    string    `json:"error,omitempty"`
	Digest   string    `json:"digest,omitempty"`
	Done     int64     `json:"done"`
	Total    int64     `json:"total"`
	Queued   time.Time `json:"queued"`
	Started  time.Time `json:"started"`
	Finished time.Time `json:"finished"`
	By       string    `json:"by,omitempty"`
}

type transfers struct {
	mu      sync.Mutex
	jobs    map[string]*TransferView
	sem     chan struct{}
	limit   int64
	scratch string
	// guard refuses loopback and link-local import sources. Always on in production.
	guard  bool
	ctx    context.Context
	cancel context.CancelFunc
}

func newTransfers() *transfers {
	ctx, cancel := context.WithCancel(context.Background())
	return &transfers{jobs: map[string]*TransferView{}, sem: make(chan struct{}, maxConcurrentTransfers),
		limit: DefaultImportLimit, scratch: filepath.Join(os.TempDir(), "stowage-uploads"), guard: true, ctx: ctx, cancel: cancel}
}

// SetImportLimit sets the largest image (bytes) that may be added; 0 keeps the default.
func (s *Service) SetImportLimit(n int64) {
	if n > 0 {
		s.tr.limit = n
	}
}

// ImportLimit is the largest image, in bytes, that imports and uploads accept.
func (s *Service) ImportLimit() int64 { return s.tr.limit }

// SetScratchDir sets where uploaded archives are staged while they are pushed.
func (s *Service) SetScratchDir(dir string) { s.tr.scratch = filepath.Join(dir, "uploads") }

// ImportInput asks Stowage to copy an image from another registry.
type ImportInput struct {
	Source       string `json:"source"`   // e.g. docker.io/library/alpine:3.19 or registry.example.com/team/app@sha256:...
	Username     string `json:"username"` // optional, for a private source
	Password     string `json:"password"`
	SkipTLS      bool   `json:"skipTLS"`      // source has a self-signed certificate
	AllPlatforms bool   `json:"allPlatforms"` // keep a multi-architecture image whole; default is this host's platform only
	Repo         string `json:"repo"`         // destination repository in this registry
	Tag          string `json:"tag"`
	Overwrite    bool   `json:"overwrite"` // replace the tag if it exists
	Scan         bool   `json:"scan"`      // queue a security scan when done
}

// prepare validates the destination and returns the registry access for the transfer.
func (s *Service) prepare(ctx context.Context, registry, repo, tag string, overwrite bool) (access, error) {
	if !regclient.ValidRepo(repo) {
		return access{}, fmt.Errorf("%w: invalid repository name (lowercase letters, digits, . _ - and / between parts)", ErrInvalid)
	}
	if !tagRe.MatchString(tag) {
		return access{}, fmt.Errorf("%w: invalid tag", ErrInvalid)
	}
	a, err := s.toolAccess(ctx, registry)
	if err != nil {
		return access{}, err
	}
	if !overwrite {
		c := regclient.NewManaged(scheme2(a)+"://"+a.endpoint, a.user, a.pass)
		switch _, err := c.Digest(ctx, repo, tag); {
		case err == nil:
			return access{}, fmt.Errorf("%w: %s:%s already exists; choose \"Replace the existing tag\" to overwrite it", ErrExists, repo, tag)
		case errors.Is(err, regclient.ErrNotFound):
		default:
			return access{}, mapReg(err)
		}
	}
	return a, nil
}

func scheme2(a access) string {
	if a.tls {
		return "https"
	}
	return "http"
}

func (t *transfers) newJob(kind, registry, repo, tag, source, by string) (*TransferView, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now().UTC()
	for id, j := range t.jobs { // forget old finished jobs
		if (j.Status == TransferDone || j.Status == TransferFailed) && now.Sub(j.Finished) > time.Hour {
			delete(t.jobs, id)
		}
	}
	for _, j := range t.jobs {
		if j.Registry == registry && j.Repo == repo && j.Tag == tag && (j.Status == TransferQueued || j.Status == TransferRunning) {
			return nil, ErrTransferBusy
		}
	}
	j := &TransferView{ID: randID(), Kind: kind, Registry: registry, Repo: repo, Tag: tag, Source: source, Status: TransferQueued, Queued: now, By: by}
	t.jobs[j.ID] = j
	return j, nil
}

func (t *transfers) update(id string, f func(*TransferView)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if j := t.jobs[id]; j != nil {
		f(j)
	}
}

func (t *transfers) get(id string) (TransferView, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if j := t.jobs[id]; j != nil {
		return *j, true
	}
	return TransferView{}, false
}

// Transfers lists a registry's recent add-image jobs, newest first.
func (s *Service) Transfers(registry string) ([]TransferView, error) {
	if _, err := s.st.Get(registry); err != nil {
		return nil, err
	}
	s.tr.mu.Lock()
	defer s.tr.mu.Unlock()
	out := []TransferView{}
	for _, j := range s.tr.jobs {
		if j.Registry == registry {
			out = append(out, *j)
		}
	}
	sort.Slice(out, func(i, k int) bool { return out[i].Queued.After(out[k].Queued) })
	return out, nil
}

// run executes work under the concurrency limit, tracks progress and records the outcome.
func (s *Service) run(id string, scan bool, work func(ctx context.Context, progress func(done, total int64)) (string, error)) {
	t := s.tr
	select {
	case t.sem <- struct{}{}:
		defer func() { <-t.sem }()
	case <-t.ctx.Done():
		t.update(id, func(j *TransferView) {
			j.Status, j.Error, j.Finished = TransferFailed, "Stowage is shutting down", time.Now().UTC()
		})
		return
	}
	t.update(id, func(j *TransferView) { j.Status, j.Started = TransferRunning, time.Now().UTC() })
	ctx, cancel := context.WithTimeout(t.ctx, 2*time.Hour)
	defer cancel()

	digest, err := func() (d string, err error) {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("internal error: %v", r)
			}
		}()
		return work(ctx, func(done, total int64) {
			// Updates can still be buffered when the job ends; they must not overwrite the final numbers.
			t.update(id, func(j *TransferView) {
				if j.Status == TransferRunning {
					j.Done, j.Total = done, total
				}
			})
		})
	}()

	v, _ := t.get(id)
	entry := store.AuditEntry{Actor: v.By, Action: "registry.image.transfer", Target: v.Registry, Outcome: "ok",
		Detail: map[string]string{"kind": v.Kind, "repo": v.Repo, "tag": v.Tag}}
	t.update(id, func(j *TransferView) {
		j.Finished = time.Now().UTC()
		if err != nil {
			j.Status, j.Error = TransferFailed, userError(err)
			return
		}
		j.Status, j.Digest = TransferDone, digest
		if j.Total > 0 {
			j.Done = j.Total
		}
	})
	if err != nil {
		entry.Outcome, entry.Detail["error"] = "error", userError(err)
	} else {
		entry.Detail["digest"] = digest
	}
	_ = s.st.AddAudit(entry)
	if err == nil && scan && s.sec != nil {
		_, _, _ = s.StartScans(context.Background(), v.Registry, v.Repo, digest, []string{KindVuln, KindSBOM, KindSig}, v.By)
	}
}

// userError turns library errors into messages a person can act on, without leaking secrets.
func userError(err error) string {
	msg := err.Error()
	l := strings.ToLower(msg)
	switch {
	case strings.Contains(l, "unauthorized"), strings.Contains(l, "authentication required"):
		return "The source registry rejected the credentials, or the image is private. Add a username and password."
	case strings.Contains(l, "manifest unknown"), strings.Contains(l, "manifest_unknown"), strings.Contains(l, "name unknown"), strings.Contains(l, "name_unknown"), strings.Contains(l, "not found"):
		return "The source registry has no such image or tag."
	case strings.Contains(l, "refusing to connect"):
		return "Importing from loopback or link-local addresses is not allowed."
	case strings.Contains(l, "x509"), strings.Contains(l, "certificate"):
		return "The source's TLS certificate is not trusted. If it is self-signed, tick \"Source uses a self-signed certificate\"."
	case strings.Contains(l, "no such host"), strings.Contains(l, "dial tcp"), strings.Contains(l, "i/o timeout"):
		return "Could not reach the source registry: " + firstLine(msg)
	case errors.Is(err, context.DeadlineExceeded):
		return "The transfer took longer than two hours and was stopped."
	}
	if len(msg) > 400 {
		msg = msg[:400] + "…"
	}
	return msg
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// ---- destination ----

func (s *Service) destination(a access, repo, tag string) (name.Reference, []remote.Option, error) {
	opts := []name.Option{name.WeakValidation}
	if !a.tls {
		opts = append(opts, name.Insecure)
	}
	ref, err := name.ParseReference(a.endpoint+"/"+repo+":"+tag, opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	tr := remote.DefaultTransport.(*http.Transport).Clone()
	if a.tls {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // our own instance, usually self-signed
	}
	return ref, []remote.Option{remote.WithAuth(authn.FromConfig(authn.AuthConfig{Username: a.user, Password: a.pass})), remote.WithTransport(tr)}, nil
}

func imageSize(img v1.Image) (int64, error) {
	m, err := img.Manifest()
	if err != nil {
		return 0, err
	}
	n := m.Config.Size
	for _, l := range m.Layers {
		n += l.Size
	}
	return n, nil
}

// pushProgress wires remote's progress channel to the job without leaking a goroutine.
func pushProgress(progress func(done, total int64)) (opt remote.Option, stop func()) {
	ch := make(chan v1.Update, 32)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case u, ok := <-ch:
				if !ok {
					return
				}
				progress(u.Complete, u.Total)
			case <-done:
				return
			}
		}
	}()
	return remote.WithProgress(ch), func() { close(done) }
}

// ---- import from another registry ----

// ImportImage starts copying an image from another registry into this one.
func (s *Service) ImportImage(ctx context.Context, registry string, in ImportInput, by string) (TransferView, error) {
	in.Source = strings.TrimSpace(in.Source)
	if in.Source == "" || len(in.Source) > 512 {
		return TransferView{}, fmt.Errorf("%w: give a source image, e.g. docker.io/library/alpine:3.19", ErrInvalid)
	}
	src, err := name.ParseReference(in.Source)
	if err != nil {
		return TransferView{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	a, err := s.prepare(ctx, registry, in.Repo, in.Tag, in.Overwrite)
	if err != nil {
		return TransferView{}, err
	}
	job, err := s.tr.newJob("import", registry, in.Repo, in.Tag, in.Source, by)
	if err != nil {
		return TransferView{}, err
	}
	view := *job
	go s.run(job.ID, in.Scan, func(ctx context.Context, progress func(done, total int64)) (string, error) {
		return s.doImport(ctx, a, src, in, progress)
	})
	return view, nil
}

func (s *Service) doImport(ctx context.Context, a access, src name.Reference, in ImportInput, progress func(done, total int64)) (string, error) {
	tr := remote.DefaultTransport.(*http.Transport).Clone()
	if s.tr.guard {
		tr.DialContext = guardedDial(&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second})
	}
	if in.SkipTLS {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	auth := authn.Anonymous
	if in.Username != "" || in.Password != "" {
		auth = authn.FromConfig(authn.AuthConfig{Username: in.Username, Password: in.Password})
	}
	srcOpts := []remote.Option{remote.WithContext(ctx), remote.WithAuth(auth), remote.WithTransport(tr),
		remote.WithPlatform(v1.Platform{OS: "linux", Architecture: gort.GOARCH})}

	desc, err := remote.Get(src, srcOpts...)
	if err != nil {
		return "", err
	}
	dst, dstOpts, err := s.destination(a, in.Repo, in.Tag)
	if err != nil {
		return "", err
	}
	dstOpts = append(dstOpts, remote.WithContext(ctx))
	progOpt, stop := pushProgress(progress)
	defer stop()
	dstOpts = append(dstOpts, progOpt)

	if desc.MediaType.IsIndex() && in.AllPlatforms {
		idx, err := desc.ImageIndex()
		if err != nil {
			return "", err
		}
		total, err := s.indexSize(idx)
		if err != nil {
			return "", err
		}
		if total > s.tr.limit {
			return "", fmt.Errorf("%w: the image is %s, above the %s limit", ErrInvalid, humanBytes(total), humanBytes(s.tr.limit))
		}
		if err := remote.WriteIndex(dst, idx, dstOpts...); err != nil {
			return "", err
		}
		d, err := idx.Digest()
		return d.String(), err
	}
	img, err := desc.Image()
	if err != nil {
		return "", err
	}
	size, err := imageSize(img)
	if err != nil {
		return "", err
	}
	if size > s.tr.limit {
		return "", fmt.Errorf("%w: the image is %s, above the %s limit", ErrInvalid, humanBytes(size), humanBytes(s.tr.limit))
	}
	if err := remote.Write(dst, img, dstOpts...); err != nil {
		return "", err
	}
	d, err := img.Digest()
	return d.String(), err
}

func (s *Service) indexSize(idx v1.ImageIndex) (int64, error) {
	im, err := idx.IndexManifest()
	if err != nil {
		return 0, err
	}
	var total int64
	for _, m := range im.Manifests {
		if m.MediaType.IsImage() {
			img, err := idx.Image(m.Digest)
			if err != nil {
				return 0, err
			}
			n, err := imageSize(img)
			if err != nil {
				return 0, err
			}
			total += n
		}
	}
	return total, nil
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// ---- upload an archive ----

// UploadImage stores a docker-archive (podman save / docker save) uploaded by the user and pushes
// it into the registry in the background. The body is staged on disk first.
func (s *Service) UploadImage(ctx context.Context, registry, repo, tag, filename string, body io.Reader, overwrite, scan bool, by string) (TransferView, error) {
	a, err := s.prepare(ctx, registry, repo, tag, overwrite)
	if err != nil {
		return TransferView{}, err
	}
	if err := os.MkdirAll(s.tr.scratch, 0o700); err != nil {
		return TransferView{}, err
	}
	dir, err := os.MkdirTemp(s.tr.scratch, "upload-")
	if err != nil {
		return TransferView{}, err
	}
	path := filepath.Join(dir, "image.tar")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		os.RemoveAll(dir)
		return TransferView{}, err
	}
	limit := s.tr.limit
	n, err := io.Copy(f, io.LimitReader(body, limit+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil || n > limit || n == 0 {
		os.RemoveAll(dir)
		switch {
		case err != nil:
			return TransferView{}, fmt.Errorf("upload interrupted: %w", err)
		case n == 0:
			return TransferView{}, fmt.Errorf("%w: the file is empty", ErrInvalid)
		}
		return TransferView{}, fmt.Errorf("%w: the file is larger than the %s limit", ErrInvalid, humanBytes(limit))
	}
	job, err := s.tr.newJob("upload", registry, repo, tag, filepath.Base(filename), by)
	if err != nil {
		os.RemoveAll(dir)
		return TransferView{}, err
	}
	view := *job
	go func() {
		defer os.RemoveAll(dir)
		s.run(job.ID, scan, func(ctx context.Context, progress func(done, total int64)) (string, error) {
			return s.doUpload(ctx, a, path, repo, tag, progress)
		})
	}()
	return view, nil
}

// archiveOpener opens a plain or gzip-compressed archive.
func archiveOpener(path string) tarball.Opener {
	return func() (io.ReadCloser, error) {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		magic := make([]byte, 2)
		if _, err := io.ReadFull(f, magic); err != nil {
			f.Close()
			return nil, err
		}
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			f.Close()
			return nil, err
		}
		if magic[0] != 0x1f || magic[1] != 0x8b {
			return f, nil
		}
		gz, err := gzip.NewReader(f)
		if err != nil {
			f.Close()
			return nil, err
		}
		return struct {
			io.Reader
			io.Closer
		}{gz, closeBoth{gz, f}}, nil
	}
}

type closeBoth struct{ a, b io.Closer }

func (c closeBoth) Close() error {
	e1 := c.a.Close()
	e2 := c.b.Close()
	if e1 != nil {
		return e1
	}
	return e2
}

func (s *Service) doUpload(ctx context.Context, a access, path, repo, tag string, progress func(done, total int64)) (string, error) {
	open := archiveOpener(path)
	m, err := tarball.LoadManifest(open)
	if err != nil || len(m) == 0 {
		return "", errors.New("this is not a docker-archive file. Create one with `podman save -o image.tar IMAGE` (or `docker save`); OCI-format archives are not supported")
	}
	if len(m) > 1 {
		return "", fmt.Errorf("the archive contains %d images; save one image at a time", len(m))
	}
	img, err := tarball.Image(open, nil)
	if err != nil {
		return "", fmt.Errorf("could not read the archive: %w", err)
	}
	size, err := imageSize(img)
	if err != nil {
		return "", err
	}
	if size > s.tr.limit {
		return "", fmt.Errorf("%w: the image is %s, above the %s limit", ErrInvalid, humanBytes(size), humanBytes(s.tr.limit))
	}
	dst, dstOpts, err := s.destination(a, repo, tag)
	if err != nil {
		return "", err
	}
	progOpt, stop := pushProgress(progress)
	defer stop()
	dstOpts = append(dstOpts, remote.WithContext(ctx), progOpt)
	if err := remote.Write(dst, img, dstOpts...); err != nil {
		return "", err
	}
	d, err := img.Digest()
	return d.String(), err
}
