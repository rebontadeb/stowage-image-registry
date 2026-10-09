package service

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/rdeb/local-image-registry/internal/imgfs"
	"github.com/rdeb/local-image-registry/internal/regclient"
	"github.com/rdeb/local-image-registry/internal/runtime"
	"github.com/rdeb/local-image-registry/internal/scanparse"
	"github.com/rdeb/local-image-registry/internal/store"
	"github.com/rdeb/local-image-registry/internal/vault"
)

// Scan kinds.
const (
	KindVuln = "vuln" // grype: known vulnerabilities
	KindSBOM = "sbom" // syft: software bill of materials
	KindSig  = "sig"  // cosign: signature status
	KindOVAL = "oval" // openscap: Red Hat OVAL advisories (RHEL-based images)
)

var (
	ErrSecurityDisabled = errors.New("security scanning is not enabled on this server")
	ErrNoSigningKey     = errors.New("this registry has no signing key")

	digestRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	kindRe   = map[string]time.Duration{KindVuln: 25 * time.Minute, KindSBOM: 15 * time.Minute, KindSig: 5 * time.Minute, KindOVAL: 40 * time.Minute}
)

// ToolImages names the tool container images the engine runs.
type ToolImages struct{ Syft, Grype, Cosign, OpenSCAP string }

func DefaultToolImages() ToolImages {
	return ToolImages{
		Syft:     "registry.access.redhat.com/hi/syft:latest",
		Grype:    "registry.access.redhat.com/hi/grype:latest",
		Cosign:   "registry.access.redhat.com/hi/cosign:latest",
		OpenSCAP: "registry.access.redhat.com/hi/openscap:latest",
	}
}

type SecurityConfig struct {
	Vault   *vault.Vault
	DataDir string
	Workers int
	Images  ToolImages
	// FixImage is the image whose package manager patches RHEL-based images; %s is the RHEL major version.
	// FixAlpineImage does the same for Alpine; %s is the Alpine release, e.g. 3.14.
	FixImage, FixAlpineImage string
	// FixDebianImage only needs a shell and chroot: Debian and Ubuntu images are patched by their own apt.
	FixDebianImage string
}

type scanJob struct {
	registry, repo, digest, kind, by string
}

type security struct {
	cfg    SecurityConfig
	jobs   chan scanJob
	grype  sync.Mutex // grype instances share one database directory: run them one at a time
	oval   sync.Mutex // OVAL runs unpack a whole image: one at a time
	fix    sync.Mutex // so do fixes
	ctx    context.Context
	cancel context.CancelFunc
	// pull unpacks an image into dest; replaced in tests.
	pull func(ctx context.Context, src imgfs.Source, dest string) error
}

// EnableSecurity turns on scanning, signing and compliance checks and starts the workers.
func (s *Service) EnableSecurity(cfg SecurityConfig) error {
	if s.sec != nil {
		return errors.New("security is already enabled")
	}
	if cfg.Vault == nil || cfg.DataDir == "" {
		return errors.New("security needs a vault and a data directory")
	}
	if cfg.Workers <= 0 {
		cfg.Workers = 2
	}
	d := DefaultToolImages()
	for _, p := range []struct {
		got *string
		def string
	}{{&cfg.Images.Syft, d.Syft}, {&cfg.Images.Grype, d.Grype}, {&cfg.Images.Cosign, d.Cosign}, {&cfg.Images.OpenSCAP, d.OpenSCAP}} {
		if *p.got == "" {
			*p.got = p.def
		}
	}
	if cfg.FixDebianImage == "" {
		cfg.FixDebianImage = "registry.access.redhat.com/ubi9/ubi-minimal:latest"
	}
	if cfg.FixAlpineImage == "" {
		cfg.FixAlpineImage = "docker.io/library/alpine:%s"
	}
	if cfg.FixImage == "" {
		cfg.FixImage = "registry.access.redhat.com/ubi%s/ubi-minimal:latest"
	}
	scratch := filepath.Join(cfg.DataDir, "scratch")
	if err := os.RemoveAll(scratch); err != nil { // leftovers of a crashed run
		return err
	}
	if err := os.MkdirAll(scratch, 0o700); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	sec := &security{cfg: cfg, jobs: make(chan scanJob, 256), ctx: ctx, cancel: cancel}
	sec.pull = func(ctx context.Context, src imgfs.Source, dest string) error {
		return imgfs.Pull(ctx, src, dest, imgfs.DefaultLimits)
	}
	s.sec = sec
	if err := s.st.FailInterruptedScans(); err != nil {
		return err
	}
	for i := 0; i < cfg.Workers; i++ {
		go s.worker()
	}
	return nil
}

func (s *Service) SecurityEnabled() bool { return s.sec != nil }

// Close stops the scan workers.
func (s *Service) Close() {
	s.tr.cancel()
	if s.sec != nil {
		s.sec.cancel()
	}
}

// ---- access to a registry for tools ----

type access struct {
	endpoint string
	tls      bool
	user     string
	pass     string
}

func (a access) ref(repo, digest string) string { return a.endpoint + "/" + repo + "@" + digest }

// env returns the syft/grype registry settings for the given variable prefix ("SYFT_", "GRYPE_").
func (a access) env(prefix string) map[string]string {
	e := map[string]string{
		prefix + "REGISTRY_AUTH_AUTHORITY": a.endpoint,
		prefix + "REGISTRY_AUTH_USERNAME":  a.user,
		prefix + "REGISTRY_AUTH_PASSWORD":  a.pass,
	}
	if a.tls {
		e[prefix+"REGISTRY_INSECURE_SKIP_TLS_VERIFY"] = "true" // the manager's own instance; certs are often self-signed
	} else {
		e[prefix+"REGISTRY_INSECURE_USE_HTTP"] = "true"
	}
	return e
}

// cosignEnv/cosignFlags configure cosign for this registry, with credentials via environment.
func (a access) cosignEnv() map[string]string {
	return map[string]string{"COSIGN_REGISTRY_USERNAME": a.user, "COSIGN_REGISTRY_PASSWORD": a.pass}
}

func (a access) cosignFlag() string {
	if a.tls {
		return "--allow-insecure-registry"
	}
	return "--allow-http-registry"
}

func (s *Service) toolAccess(ctx context.Context, name string) (access, error) {
	rec, err := s.st.Get(name)
	if err != nil {
		return access{}, err
	}
	st, err := s.drv.Status(ctx, name)
	if err != nil {
		return access{}, err
	}
	if !st.State.Active() || st.Endpoint == "" {
		return access{}, ErrNotRunning
	}
	return access{endpoint: st.Endpoint, tls: rec.TLSCert != "", user: adminUser, pass: rec.AdminPass}, nil
}

// redact removes secrets from text that may be shown to a user or stored.
func redact(msg string, secrets ...string) string {
	for _, sec := range secrets {
		if len(sec) >= 4 {
			msg = strings.ReplaceAll(msg, sec, "***")
		}
	}
	return msg
}

// ---- starting scans ----

type ScanView struct {
	Digest   string          `json:"digest"`
	Repo     string          `json:"repo"`
	Kind     string          `json:"kind"`
	Status   string          `json:"status"`
	Error    string          `json:"error,omitempty"`
	Tool     string          `json:"tool,omitempty"`
	Summary  json.RawMessage `json:"summary"`
	Queued   time.Time       `json:"queued"`
	Started  time.Time       `json:"started"`
	Finished time.Time       `json:"finished"`
	By       string          `json:"by,omitempty"`
}

func view(x store.Scan) ScanView {
	sum := json.RawMessage(x.Summary)
	if len(sum) == 0 {
		sum = json.RawMessage("{}")
	}
	return ScanView{Digest: x.Digest, Repo: x.Repo, Kind: x.Kind, Status: x.Status, Error: x.Error, Tool: x.Tool,
		Summary: sum, Queued: x.Queued, Started: x.Started, Finished: x.Finished, By: x.By}
}

func validKind(k string) bool { _, ok := kindRe[k]; return ok }

// StartScans queues the given kinds for the image at repo:ref (a tag or a digest).
func (s *Service) StartScans(ctx context.Context, registry, repo, ref string, kinds []string, by string) (digest string, queued []string, err error) {
	if s.sec == nil {
		return "", nil, ErrSecurityDisabled
	}
	if !regclient.ValidRepo(repo) {
		return "", nil, fmt.Errorf("%w: invalid repository name", ErrInvalid)
	}
	if len(kinds) == 0 {
		return "", nil, fmt.Errorf("%w: no scan kinds given", ErrInvalid)
	}
	for _, k := range kinds {
		if !validKind(k) {
			return "", nil, fmt.Errorf("%w: unknown scan kind %q", ErrInvalid, k)
		}
	}
	c, err := s.client(ctx, registry)
	if err != nil {
		return "", nil, err
	}
	digest = ref
	if !digestRe.MatchString(ref) {
		if digest, err = c.Digest(ctx, repo, ref); err != nil {
			return "", nil, mapReg(err)
		}
	}
	if !digestRe.MatchString(digest) {
		return "", nil, fmt.Errorf("%w: registry returned an unusable digest", ErrInvalid)
	}
	for _, k := range kinds {
		ok, err := s.st.QueueScan(registry, repo, digest, k, by)
		if err != nil {
			return "", nil, err
		}
		if !ok {
			continue // already queued or running
		}
		j := scanJob{registry, repo, digest, k, by}
		select {
		case s.sec.jobs <- j:
			queued = append(queued, k)
		default:
			_ = s.st.FinishScan(store.Scan{Registry: registry, Repo: repo, Digest: digest, Kind: k, Status: store.ScanFailed, Error: "scan queue is full; try again shortly"})
		}
	}
	return digest, queued, nil
}

func (s *Service) ScanStatuses(registry, repo string) ([]ScanView, error) {
	if _, err := s.st.Get(registry); err != nil {
		return nil, err
	}
	rows, err := s.st.ListScans(registry, repo)
	if err != nil {
		return nil, err
	}
	out := make([]ScanView, 0, len(rows))
	for _, r := range rows {
		out = append(out, view(r))
	}
	return out, nil
}

// ---- workers ----

func (s *Service) worker() {
	for {
		select {
		case <-s.sec.ctx.Done():
			return
		case j := <-s.sec.jobs:
			s.runJob(j)
		}
	}
}

type outcome struct {
	tool    string
	summary any
	result  []byte // gzip
	extra   []byte // gzip
}

func (s *Service) runJob(j scanJob) {
	fin := store.Scan{Registry: j.registry, Repo: j.repo, Digest: j.digest, Kind: j.kind}
	defer func() {
		if r := recover(); r != nil {
			fin.Status, fin.Error = store.ScanFailed, fmt.Sprintf("internal error: %v", r)
			_ = s.st.FinishScan(fin)
		}
	}()
	_ = s.st.StartScan(j.registry, j.repo, j.digest, j.kind)
	ctx, cancel := context.WithTimeout(s.sec.ctx, kindRe[j.kind])
	defer cancel()

	var (
		out outcome
		err error
	)
	a, err := s.toolAccess(ctx, j.registry)
	if err == nil {
		switch j.kind {
		case KindVuln:
			out, err = s.doVuln(ctx, j, a)
		case KindSBOM:
			out, err = s.doSBOM(ctx, j, a)
		case KindSig:
			out, err = s.doSig(ctx, j, a)
		case KindOVAL:
			out, err = s.doOVAL(ctx, j, a)
		}
	}
	if err != nil {
		fin.Status, fin.Error = store.ScanFailed, redact(err.Error(), a.pass)
		if len(fin.Error) > 600 {
			fin.Error = fin.Error[:600] + "…"
		}
		_ = s.st.FinishScan(fin)
		return
	}
	sum, _ := json.Marshal(out.summary)
	fin.Status, fin.Tool, fin.Summary, fin.Result, fin.Extra = store.ScanDone, out.tool, string(sum), out.result, out.extra
	if err := s.st.FinishScan(fin); err != nil {
		fin.Status, fin.Error, fin.Result, fin.Extra = store.ScanFailed, "could not store the result: "+err.Error(), nil, nil
		_ = s.st.FinishScan(fin)
	}
}

func (s *Service) tool(ctx context.Context, image string, a access, args []string, env map[string]string, vols []runtime.ToolVolume, timeout time.Duration) (runtime.ToolResult, error) {
	return s.drv.RunTool(ctx, runtime.ToolSpec{Image: image, Args: args, Env: env, Volumes: vols, HostNetwork: true, Timeout: timeout})
}

func toolFailure(name string, res runtime.ToolResult) error {
	msg := scanparse.Tail(res.Stderr, 400)
	if msg == "" {
		msg = scanparse.Tail(res.Stdout, 400)
	}
	return fmt.Errorf("%s failed (exit %d): %s", name, res.ExitCode, msg)
}

func (s *Service) doVuln(ctx context.Context, j scanJob, a access) (outcome, error) {
	s.sec.grype.Lock()
	defer s.sec.grype.Unlock()
	env := a.env("GRYPE_")
	env["GRYPE_DB_CACHE_DIR"] = "/db"
	res, err := s.tool(ctx, s.sec.cfg.Images.Grype, a, []string{"registry:" + a.ref(j.repo, j.digest), "-o", "json", "-q"}, env,
		[]runtime.ToolVolume{{Name: "grype-db", Dest: "/db"}}, 20*time.Minute)
	if err != nil {
		return outcome{}, err
	}
	if res.ExitCode != 0 {
		return outcome{}, toolFailure("grype", res)
	}
	rep, err := scanparse.ParseGrype(res.Stdout)
	if err != nil {
		return outcome{}, err
	}
	tool := rep.Tool
	if rep.Summary.DBBuilt != "" {
		tool += ", database built " + rep.Summary.DBBuilt
	}
	return outcome{tool: tool, summary: rep.Summary, result: gz(mustJSON(rep))}, nil
}

func (s *Service) doSBOM(ctx context.Context, j scanJob, a access) (outcome, error) {
	run := func(format string) ([]byte, error) {
		res, err := s.tool(ctx, s.sec.cfg.Images.Syft, a, []string{"registry:" + a.ref(j.repo, j.digest), "-o", format, "-q"}, a.env("SYFT_"), nil, 10*time.Minute)
		if err != nil {
			return nil, err
		}
		if res.ExitCode != 0 {
			return nil, toolFailure("syft", res)
		}
		return res.Stdout, nil
	}
	cdx, err := run("cyclonedx-json")
	if err != nil {
		return outcome{}, err
	}
	rep, err := scanparse.ParseCycloneDX(cdx)
	if err != nil {
		return outcome{}, err
	}
	spdx, err := run("spdx-json")
	if err != nil {
		return outcome{}, err
	}
	return outcome{tool: rep.Tool, summary: rep.Summary, result: gz(cdx), extra: gz(spdx)}, nil
}

// SigResult is the stored detail of a signature check.
type SigResult struct {
	Status   scanparse.SigStatus `json:"status"`
	Key      string              `json:"key,omitempty"` // label of the key that verified it
	Attempts []SigAttempt        `json:"attempts"`
}

type SigAttempt struct {
	Key    string `json:"key"`
	Status string `json:"status"`
}

func (s *Service) doSig(ctx context.Context, j scanJob, a access) (outcome, error) {
	keys, err := s.st.TrustKeys(j.registry)
	if err != nil {
		return outcome{}, err
	}
	res := SigResult{Attempts: []SigAttempt{}}
	finish := func() (outcome, error) {
		return outcome{tool: "cosign", summary: map[string]any{"status": res.Status, "key": res.Key}, result: gz(mustJSON(res))}, nil
	}
	if len(keys) == 0 {
		// Nothing to verify against: report whether a signature exists at all.
		c, err := s.client(ctx, j.registry)
		if err != nil {
			return outcome{}, err
		}
		tags, err := c.Tags(ctx, j.repo)
		if err != nil {
			return outcome{}, mapReg(err)
		}
		res.Status = scanparse.SigUnsigned
		for _, t := range tags {
			if t == sigTag(j.digest) {
				res.Status = scanparse.SigUnverified
			}
		}
		return finish()
	}

	seen := map[scanparse.SigStatus]int{}
	for _, k := range keys {
		env := a.cosignEnv()
		env["COSIGN_PUB"] = k.PublicPEM
		r, err := s.tool(ctx, s.sec.cfg.Images.Cosign, a,
			[]string{"verify", "--key", "env://COSIGN_PUB", "--insecure-ignore-tlog", a.cosignFlag(), a.ref(j.repo, j.digest)}, env, nil, 3*time.Minute)
		if err != nil {
			return outcome{}, err
		}
		verified, st, ok := scanparse.ClassifyCosign(r.ExitCode, string(r.Stderr)+string(r.Stdout))
		if !ok {
			return outcome{}, toolFailure("cosign", r)
		}
		res.Attempts = append(res.Attempts, SigAttempt{Key: k.Label, Status: string(st)})
		seen[st]++
		if verified {
			res.Status, res.Key = scanparse.SigSigned, k.Label
			return finish()
		}
	}
	// Not verified by any key: distinguish "no signature at all" from "signed by someone else".
	if seen[scanparse.SigInvalid] > 0 {
		res.Status = scanparse.SigInvalid
	} else {
		res.Status = scanparse.SigUnsigned
	}
	return finish()
}

// sigTag is the tag cosign stores an image's signatures under when the registry has no referrers API.
func sigTag(digest string) string { return strings.Replace(digest, ":", "-", 1) }

func (s *Service) doOVAL(ctx context.Context, j scanJob, a access) (outcome, error) {
	s.sec.oval.Lock()
	defer s.sec.oval.Unlock()
	scratch, err := os.MkdirTemp(filepath.Join(s.sec.cfg.DataDir, "scratch"), "oval-")
	if err != nil {
		return outcome{}, err
	}
	defer os.RemoveAll(scratch)
	rootfs, outDir := filepath.Join(scratch, "root"), filepath.Join(scratch, "out")
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return outcome{}, err
	}
	if err := s.sec.pull(ctx, imgfs.Source{Ref: a.ref(j.repo, j.digest), Username: a.user, Password: a.pass, HTTP: !a.tls, SkipTLS: a.tls}, rootfs); err != nil {
		return outcome{}, errors.New(redact(err.Error(), a.pass))
	}

	osName, id, major := readOSRelease(rootfs)
	na := func(reason string) (outcome, error) {
		sum := scanparse.OVALSummary{Applicable: false, Reason: reason, OS: osName}
		return outcome{tool: "oscap", summary: sum, result: gz(mustJSON(scanparse.OVALReport{Summary: sum, Findings: []scanparse.OVALFinding{}}))}, nil
	}
	if id != "rhel" {
		return na("Not a RHEL-based image. Red Hat OVAL content covers RHEL and UBI images only.")
	}
	contentName := "rhel-" + major
	c, err := s.st.GetSCAPContent(contentName)
	if errors.Is(err, store.ErrNotFound) {
		return outcome{}, fmt.Errorf("no OVAL content named %q in the library: add it under Administration → Security tools", contentName)
	}
	if err != nil {
		return outcome{}, err
	}
	contentDir := filepath.Join(s.sec.cfg.DataDir, "scap", c.Name)

	res, err := s.drv.RunTool(ctx, runtime.ToolSpec{
		Image: s.sec.cfg.Images.OpenSCAP,
		Args:  []string{"oval", "eval", "--results", "/out/results.xml", "--report", "/out/report.html", "/content/" + c.Filename},
		Env:   map[string]string{"OSCAP_PROBE_ROOT": "/target"},
		Mounts: []runtime.ToolMount{
			{Host: rootfs, Dest: "/target", ReadOnly: true},
			{Host: contentDir, Dest: "/content", ReadOnly: true},
			{Host: outDir, Dest: "/out"},
		},
		// The rpm probe chroot()s into the image. Container root in a rootless user namespace is
		// still the invoking user on the host; only CHROOT is granted on top of "drop all".
		Root: true, Caps: []string{"SYS_CHROOT"}, Timeout: 30 * time.Minute,
	})
	if err != nil {
		return outcome{}, err
	}
	f, ferr := os.Open(filepath.Join(outDir, "results.xml"))
	if res.ExitCode != 0 && ferr != nil {
		return outcome{}, toolFailure("oscap", res)
	}
	if ferr != nil {
		return outcome{}, fmt.Errorf("oscap produced no results: %w", ferr)
	}
	defer f.Close()
	rep, err := scanparse.ParseOVALResults(f)
	if err != nil {
		return outcome{}, err
	}
	rep.Summary.OS, rep.Summary.Content = osName, c.Name
	html, _ := os.ReadFile(filepath.Join(outDir, "report.html"))
	return outcome{tool: "oscap, " + c.Name + " (" + c.SHA256[:12] + ")", summary: rep.Summary, result: gz(mustJSON(rep)), extra: gz(html)}, nil
}

// readOSRelease reads the image's os-release file confined to the unpacked tree, so a symlink
// in the (untrusted) image cannot make us read a file of the host.
func readOSRelease(rootfs string) (pretty, id, major string) {
	kv := readOSReleaseKV(rootfs)
	major, _, _ = strings.Cut(kv["VERSION_ID"], ".")
	return kv["PRETTY_NAME"], kv["ID"], major
}

func readOSReleaseKV(rootfs string) map[string]string {
	root, err := os.OpenRoot(rootfs)
	if err != nil {
		return nil
	}
	defer root.Close()
	for _, p := range []string{"etc/os-release", "usr/lib/os-release"} {
		f, err := root.Open(p)
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(f, 16<<10))
		f.Close()
		kv := map[string]string{}
		for _, line := range strings.Split(string(b), "\n") {
			if k, v, ok := strings.Cut(line, "="); ok {
				kv[k] = strings.Trim(strings.TrimSpace(v), `"'`)
			}
		}
		return kv
	}
	return nil
}

// ---- reading results ----

func (s *Service) scan(registry, repo, digest, kind string) (store.Scan, error) {
	if !digestRe.MatchString(digest) || !validKind(kind) || !regclient.ValidRepo(repo) {
		return store.Scan{}, fmt.Errorf("%w: bad repository, digest or kind", ErrInvalid)
	}
	sc, err := s.st.GetScan(registry, repo, digest, kind)
	if err != nil {
		return sc, err
	}
	if sc.Status != store.ScanDone {
		return sc, fmt.Errorf("%w: scan is %s", ErrNotReady, sc.Status)
	}
	return sc, nil
}

var ErrNotReady = errors.New("result not available")

// ScanDetail returns the parsed result of a finished scan.
func (s *Service) ScanDetail(registry, repo, digest, kind string) (any, error) {
	sc, err := s.scan(registry, repo, digest, kind)
	if err != nil {
		return nil, err
	}
	raw, err := gunzip(sc.Result)
	if err != nil {
		return nil, err
	}
	if kind == KindSBOM {
		return scanparse.ParseCycloneDX(raw)
	}
	return json.RawMessage(raw), nil
}

// Download returns a stored artifact: "cyclonedx", "spdx" or "oval-report".
func (s *Service) Download(registry, repo, digest, what string) (data []byte, filename, contentType string, err error) {
	kind, useExtra, ct, ext := "", false, "application/json", ".json"
	switch what {
	case "cyclonedx":
		kind = KindSBOM
	case "spdx":
		kind, useExtra = KindSBOM, true
	case "oval-report":
		kind, useExtra, ct, ext = KindOVAL, true, "text/html; charset=utf-8", ".html"
	default:
		return nil, "", "", fmt.Errorf("%w: unknown download %q", ErrInvalid, what)
	}
	sc, err := s.scan(registry, repo, digest, kind)
	if err != nil {
		return nil, "", "", err
	}
	blob := sc.Result
	if useExtra {
		blob = sc.Extra
	}
	if data, err = gunzip(blob); err != nil || len(data) == 0 {
		return nil, "", "", fmt.Errorf("%w: nothing stored", ErrNotReady)
	}
	base := strings.NewReplacer("/", "_", ":", "_").Replace(repo) + "-" + digest[7:19]
	return data, base + "-" + what + ext, ct, nil
}

// ---- helpers ----

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func gz(b []byte) []byte {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, _ = w.Write(b)
	_ = w.Close()
	return buf.Bytes()
}

func gunzip(b []byte) ([]byte, error) {
	if len(b) == 0 {
		return nil, nil
	}
	r, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(io.LimitReader(r, 512<<20))
}

func randID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func fingerprint(pubDER []byte) string {
	h := sha256.Sum256(pubDER)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(h[:])
}

// ---- small shared helpers ----

func vaultRandom() (string, error) { return vault.RandomPassword() }

type headCapture struct{ buf *[]byte }

func (h *headCapture) Write(p []byte) (int, error) {
	if room := cap(*h.buf) - len(*h.buf); room > 0 {
		if len(p) < room {
			room = len(p)
		}
		*h.buf = append(*h.buf, p[:room]...)
	}
	return len(p), nil
}

func newSHA() hash.Hash { return sha256.New() }

func hexSum(h hash.Hash) string { return hex.EncodeToString(h.Sum(nil)) }
