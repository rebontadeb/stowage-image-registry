package service

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"

	"github.com/rdeb/local-image-registry/internal/runtime/fake"
	"github.com/rdeb/local-image-registry/internal/store"
)

// xrig has a real (in-memory) source registry, a real destination registry that stands in for the
// tenant's, and the service wired between them.
type xrig struct {
	svc     *Service
	st      *store.Store
	srcHost string
	dstHost string
}

func newXRig(t *testing.T) *xrig {
	t.Helper()
	src := httptest.NewServer(registry.New())
	dst := httptest.NewServer(registry.New())
	t.Cleanup(src.Close)
	t.Cleanup(dst.Close)
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	drv := fake.New()
	svc := New(st, drv, 5100, 5199)
	svc.SetReadyTimeout(0)
	svc.SetScratchDir(t.TempDir())
	t.Cleanup(svc.Close)
	svc.tr.guard = false // the test sources are on loopback
	if _, err := svc.Create(context.Background(), CreateInput{Name: "acme", Customer: "Acme"}); err != nil {
		t.Fatal(err)
	}
	drv.Endpoints = map[string]string{"acme": strings.TrimPrefix(dst.URL, "http://")}
	return &xrig{svc: svc, st: st, srcHost: strings.TrimPrefix(src.URL, "http://"), dstHost: strings.TrimPrefix(dst.URL, "http://")}
}

func (x *xrig) pushSource(t *testing.T, repo, tag string, img v1.Image) {
	t.Helper()
	ref, err := name.ParseReference(x.srcHost + "/" + repo + ":" + tag)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(ref, img); err != nil {
		t.Fatal(err)
	}
}

func (x *xrig) destDigest(t *testing.T, repo, tag string) (string, error) {
	t.Helper()
	ref, _ := name.ParseReference(x.dstHost + "/" + repo + ":" + tag)
	d, err := remote.Head(ref)
	if err != nil {
		return "", err
	}
	return d.Digest.String(), nil
}

func (x *xrig) await(t *testing.T, id string) TransferView {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if v, ok := x.svc.tr.get(id); ok && (v.Status == TransferDone || v.Status == TransferFailed) {
			return v
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("transfer never finished")
	return TransferView{}
}

func TestImportCopiesTheImageByteForByte(t *testing.T) {
	x := newXRig(t)
	img, _ := random.Image(4096, 3)
	want, _ := img.Digest()
	x.pushSource(t, "library/app", "1.0", img)

	v, err := x.svc.ImportImage(context.Background(), "acme", ImportInput{Source: x.srcHost + "/library/app:1.0", Repo: "team/app", Tag: "stable"}, "olivia")
	if err != nil || v.Status != TransferQueued || v.Kind != "import" {
		t.Fatalf("%+v %v", v, err)
	}
	done := x.await(t, v.ID)
	if done.Status != TransferDone || done.Digest != want.String() || done.Total == 0 || done.Done != done.Total {
		t.Fatalf("%+v", done)
	}
	if got, err := x.destDigest(t, "team/app", "stable"); err != nil || got != want.String() {
		t.Fatalf("destination has %q (%v), want %s", got, err, want)
	}
	// the outcome is in the audit log, with no credentials
	entries, _ := x.st.QueryAudit(store.AuditFilter{Action: "registry.image.transfer"})
	if len(entries) != 1 || entries[0].Outcome != "ok" || entries[0].Actor != "olivia" || entries[0].Detail["digest"] != want.String() {
		t.Fatalf("audit: %+v", entries)
	}
}

func TestImportOverwriteProtectionAndConflicts(t *testing.T) {
	x := newXRig(t)
	a, _ := random.Image(1024, 1)
	b, _ := random.Image(1024, 1)
	x.pushSource(t, "a", "v", a)
	x.pushSource(t, "b", "v", b)
	ctx := context.Background()
	in := ImportInput{Source: x.srcHost + "/a:v", Repo: "team/app", Tag: "latest"}

	v, err := x.svc.ImportImage(ctx, "acme", in, "u")
	if err != nil {
		t.Fatal(err)
	}
	x.await(t, v.ID)

	in2 := ImportInput{Source: x.srcHost + "/b:v", Repo: "team/app", Tag: "latest"}
	if _, err := x.svc.ImportImage(ctx, "acme", in2, "u"); !errors.Is(err, ErrExists) {
		t.Fatalf("existing tag must not be replaced silently: %v", err)
	}
	if got, _ := x.destDigest(t, "team/app", "latest"); got != mustDigest(a) {
		t.Fatal("tag changed without overwrite")
	}
	in2.Overwrite = true
	v, err = x.svc.ImportImage(ctx, "acme", in2, "u")
	if err != nil {
		t.Fatal(err)
	}
	x.await(t, v.ID)
	if got, _ := x.destDigest(t, "team/app", "latest"); got != mustDigest(b) {
		t.Fatalf("overwrite did not replace the tag: %s", got)
	}
}

func mustDigest(img v1.Image) string { d, _ := img.Digest(); return d.String() }

func TestImportRejectsBadInputBeforeDoingAnything(t *testing.T) {
	x := newXRig(t)
	ctx := context.Background()
	for name, in := range map[string]ImportInput{
		"no source":        {Repo: "a", Tag: "t"},
		"junk source":      {Source: "not a ref!!", Repo: "a", Tag: "t"},
		"huge source":      {Source: strings.Repeat("a", 600), Repo: "a", Tag: "t"},
		"uppercase repo":   {Source: "alpine:3", Repo: "Team/App", Tag: "t"},
		"traversal repo":   {Source: "alpine:3", Repo: "../x", Tag: "t"},
		"repo with digest": {Source: "alpine:3", Repo: "a@sha256:" + strings.Repeat("a", 64), Tag: "t"},
		"bad tag":          {Source: "alpine:3", Repo: "a", Tag: "bad/tag"},
		"empty tag":        {Source: "alpine:3", Repo: "a"},
	} {
		if _, err := x.svc.ImportImage(ctx, "acme", in, "u"); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: want ErrInvalid, got %v", name, err)
		}
	}
	if _, err := x.svc.ImportImage(ctx, "nope", ImportInput{Source: "alpine:3", Repo: "a", Tag: "t"}, "u"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown registry: %v", err)
	}
	if jobs, _ := x.svc.Transfers("acme"); len(jobs) != 0 {
		t.Fatalf("rejected requests must not create jobs: %+v", jobs)
	}
}

func TestImportSizeLimitAndUnknownSource(t *testing.T) {
	x := newXRig(t)
	big, _ := random.Image(50_000, 2)
	x.pushSource(t, "big", "v", big)
	x.svc.SetImportLimit(10_000)
	v, _ := x.svc.ImportImage(context.Background(), "acme", ImportInput{Source: x.srcHost + "/big:v", Repo: "a", Tag: "t"}, "u")
	done := x.await(t, v.ID)
	if done.Status != TransferFailed || !strings.Contains(done.Error, "limit") {
		t.Fatalf("size limit: %+v", done)
	}
	if _, err := x.destDigest(t, "a", "t"); err == nil {
		t.Fatal("an over-limit image was pushed anyway")
	}
	x.svc.SetImportLimit(DefaultImportLimit)
	v, _ = x.svc.ImportImage(context.Background(), "acme", ImportInput{Source: x.srcHost + "/missing:v", Repo: "a", Tag: "t2"}, "u")
	done = x.await(t, v.ID)
	if done.Status != TransferFailed || !strings.Contains(done.Error, "no such image") {
		t.Fatalf("missing source should explain itself: %+v", done)
	}
	entries, _ := x.st.QueryAudit(store.AuditFilter{Action: "registry.image.transfer", Outcome: "error"})
	if len(entries) != 2 {
		t.Fatalf("failures must be audited: %d", len(entries))
	}
}

func TestImportMultiArchDefaultsToHostPlatformUnlessAllRequested(t *testing.T) {
	x := newXRig(t)
	mk := func(arch string) mutate.IndexAddendum {
		img, _ := random.Image(512, 1)
		cf, _ := img.ConfigFile()
		cf.Architecture, cf.OS = arch, "linux"
		img, _ = mutate.ConfigFile(img, cf)
		return mutate.IndexAddendum{Add: img, Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: arch}}}
	}
	idx := mutate.AppendManifests(empty.Index, mk("amd64"), mk("arm64"))
	ref, _ := name.ParseReference(x.srcHost + "/multi:v")
	if err := remote.WriteIndex(ref, idx); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	v, _ := x.svc.ImportImage(ctx, "acme", ImportInput{Source: x.srcHost + "/multi:v", Repo: "one", Tag: "t"}, "u")
	one := x.await(t, v.ID)
	v, _ = x.svc.ImportImage(ctx, "acme", ImportInput{Source: x.srcHost + "/multi:v", Repo: "all", Tag: "t", AllPlatforms: true}, "u")
	all := x.await(t, v.ID)
	if one.Status != TransferDone || all.Status != TransferDone {
		t.Fatalf("%+v %+v", one, all)
	}
	wantIdx, _ := idx.Digest()
	if all.Digest != wantIdx.String() {
		t.Fatalf("all-platforms copy must keep the index intact: %s vs %s", all.Digest, wantIdx)
	}
	if one.Digest == wantIdx.String() {
		t.Fatal("default copy should be a single platform, not the whole index")
	}
}

func TestUploadPushesADockerArchive(t *testing.T) {
	x := newXRig(t)
	img, _ := random.Image(2048, 2)
	var buf bytes.Buffer
	tag, _ := name.NewTag("example.com/app:1.0")
	if err := tarball.Write(tag, img, &buf); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	v, err := x.svc.UploadImage(ctx, "acme", "team/app", "1.0", "../../etc/app.tar", bytes.NewReader(buf.Bytes()), false, false, "olivia")
	if err != nil || v.Kind != "upload" || v.Source != "app.tar" {
		t.Fatalf("file name must be reduced to its base: %+v %v", v, err)
	}
	done := x.await(t, v.ID)
	if done.Status != TransferDone || done.Digest != mustDigest(img) {
		t.Fatalf("%+v", done)
	}
	if got, _ := x.destDigest(t, "team/app", "1.0"); got != mustDigest(img) {
		t.Fatalf("pushed digest %s", got)
	}
	// the staged archive is removed afterwards
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if entries, _ := filepath.Glob(filepath.Join(x.svc.tr.scratch, "*")); len(entries) == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("staged upload not cleaned up")
}

func TestUploadRejectsNonArchivesAndOversizeAndConflicts(t *testing.T) {
	x := newXRig(t)
	ctx := context.Background()
	v, err := x.svc.UploadImage(ctx, "acme", "a", "t", "x.tar", strings.NewReader("this is not a tar file at all"), false, false, "u")
	if err != nil {
		t.Fatal(err)
	}
	done := x.await(t, v.ID)
	if done.Status != TransferFailed || !strings.Contains(done.Error, "docker-archive") {
		t.Fatalf("junk upload should explain how to export: %+v", done)
	}
	if _, err := x.svc.UploadImage(ctx, "acme", "a", "t", "x.tar", strings.NewReader(""), false, false, "u"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty file: %v", err)
	}
	x.svc.SetImportLimit(100)
	if _, err := x.svc.UploadImage(ctx, "acme", "a", "t", "x.tar", strings.NewReader(strings.Repeat("x", 500)), false, false, "u"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("oversize: %v", err)
	}
	if entries, _ := filepath.Glob(filepath.Join(x.svc.tr.scratch, "*")); len(entries) != 0 {
		t.Fatalf("rejected upload left files behind: %v", entries)
	}
	if _, err := x.svc.UploadImage(ctx, "acme", "../x", "t", "x.tar", strings.NewReader("x"), false, false, "u"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad repo: %v", err)
	}
}

func TestUploadGzippedArchive(t *testing.T) {
	x := newXRig(t)
	img, _ := random.Image(1024, 1)
	var raw bytes.Buffer
	tag, _ := name.NewTag("example.com/app:1")
	if err := tarball.Write(tag, img, &raw); err != nil {
		t.Fatal(err)
	}
	var gzbuf bytes.Buffer
	zw := gzip.NewWriter(&gzbuf)
	zw.Write(raw.Bytes())
	zw.Close()
	v, err := x.svc.UploadImage(context.Background(), "acme", "z", "1", "app.tar.gz", &gzbuf, false, false, "u")
	if err != nil {
		t.Fatal(err)
	}
	if done := x.await(t, v.ID); done.Status != TransferDone {
		t.Fatalf("gzip archive: %+v", done)
	}
}

func TestSameDestinationCannotBeWrittenTwiceAtOnce(t *testing.T) {
	x := newXRig(t)
	for i := 0; i < maxConcurrentTransfers; i++ { // occupy every slot so the job stays queued
		x.svc.tr.sem <- struct{}{}
	}
	img, _ := random.Image(512, 1)
	x.pushSource(t, "a", "v", img)
	ctx := context.Background()
	in := ImportInput{Source: x.srcHost + "/a:v", Repo: "team/app", Tag: "t", Overwrite: true}
	first, err := x.svc.ImportImage(ctx, "acme", in, "u")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := x.svc.ImportImage(ctx, "acme", in, "u"); !errors.Is(err, ErrTransferBusy) {
		t.Fatalf("second transfer to the same tag: %v", err)
	}
	if jobs, _ := x.svc.Transfers("acme"); len(jobs) != 1 || jobs[0].Status != TransferQueued {
		t.Fatalf("queued job expected: %+v", jobs)
	}
	for i := 0; i < maxConcurrentTransfers; i++ {
		<-x.svc.tr.sem
	}
	if done := x.await(t, first.ID); done.Status != TransferDone {
		t.Fatalf("%+v", done)
	}
}

func TestSourceGuardRefusesLoopbackAndMetadata(t *testing.T) {
	x := newXRig(t)
	x.svc.tr.guard = true // production setting
	img, _ := random.Image(512, 1)
	x.pushSource(t, "a", "v", img)
	for i, src := range []string{x.srcHost + "/a:v", "127.0.0.1:1/a:v", "169.254.169.254/latest:meta", "localhost:9/a:v"} {
		v, err := x.svc.ImportImage(context.Background(), "acme", ImportInput{Source: src, Repo: "g", Tag: "t" + string(rune('a'+i))}, "u")
		if err != nil {
			t.Fatalf("%s: %v", src, err)
		}
		done := x.await(t, v.ID)
		if done.Status != TransferFailed || !strings.Contains(done.Error, "loopback or link-local") {
			t.Errorf("%s was not refused: %+v", src, done)
		}
	}
}

func TestCredentialsNeverAppearInJobsOrAudit(t *testing.T) {
	x := newXRig(t)
	v, _ := x.svc.ImportImage(context.Background(), "acme", ImportInput{Source: x.srcHost + "/missing:v", Username: "bob", Password: "hunter2-secret", Repo: "a", Tag: "t"}, "u")
	done := x.await(t, v.ID)
	all := string(mustJSON(done))
	jobs, _ := x.svc.Transfers("acme")
	entries, _ := x.st.QueryAudit(store.AuditFilter{})
	all += string(mustJSON(jobs)) + string(mustJSON(entries))
	if strings.Contains(all, "hunter2-secret") {
		t.Fatalf("password leaked: %s", all)
	}
}

func TestUserErrorMessages(t *testing.T) {
	for in, want := range map[string]string{
		"GET https://x/v2/: UNAUTHORIZED: authentication required": "rejected the credentials",
		"MANIFEST_UNKNOWN: manifest unknown":                       "no such image",
		"x509: certificate signed by unknown authority":            "self-signed",
		"dial tcp: lookup nope.invalid: no such host":              "Could not reach",
	} {
		if got := userError(errors.New(in)); !strings.Contains(got, want) {
			t.Errorf("%q -> %q", in, got)
		}
	}
	_ = http.StatusOK
}
