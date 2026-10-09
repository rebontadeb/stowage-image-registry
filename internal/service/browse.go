package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"sync"
	"syscall"

	"github.com/rdeb/local-image-registry/internal/regclient"
	"github.com/rdeb/local-image-registry/internal/runtime"
)

var ErrNotRunning = errors.New("registry is not running")

// instLocks serialises disruptive operations (GC) per registry.
var instLocks sync.Map // name -> *sync.Mutex

func lockFor(name string) *sync.Mutex {
	m, _ := instLocks.LoadOrStore(name, &sync.Mutex{})
	return m.(*sync.Mutex)
}

type TagInfo struct {
	Tag    string `json:"tag"`
	Digest string `json:"digest"`
	// Kind is "image", or "signature" for the tags cosign and friends add next to an image
	// (sha256-<digest>, and the legacy .sig/.att/.sbom suffixes). The UI hides those.
	Kind string `json:"kind"`
}

var sigTagRe = regexp.MustCompile(`^sha256-[0-9a-f]{64}(\.(sig|att|sbom))?$`)

func tagKind(tag string) string {
	if sigTagRe.MatchString(tag) {
		return "signature"
	}
	return "image"
}

type GCResult struct {
	Output      string `json:"output"`
	BytesBefore int64  `json:"bytesBefore"`
	BytesAfter  int64  `json:"bytesAfter"`
}

// client returns an API client for a running registry.
func (s *Service) client(ctx context.Context, name string) (*regclient.Client, error) {
	rec, err := s.st.Get(name)
	if err != nil {
		return nil, err
	}
	st, err := s.drv.Status(ctx, name)
	if err != nil {
		return nil, err
	}
	if st.State != runtime.StateRunning {
		return nil, ErrNotRunning
	}
	return regclient.NewManaged(scheme(rec)+"://"+st.Endpoint, adminUser, rec.AdminPass), nil
}

func mapReg(err error) error {
	switch {
	case errors.Is(err, regclient.ErrNotFound):
		return ErrNotFound
	case errors.Is(err, regclient.ErrInvalid):
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	// Connection refused/reset while the registry restarts: report "not running" (409), not a 500.
	var ne net.Error
	if errors.As(err, &ne) || errors.Is(err, io.EOF) || errors.Is(err, syscall.ECONNRESET) {
		return fmt.Errorf("%w (connection lost, try again shortly)", ErrNotRunning)
	}
	return err
}

func (s *Service) Repositories(ctx context.Context, name string) ([]string, error) {
	c, err := s.client(ctx, name)
	if err != nil {
		return nil, err
	}
	repos, err := c.Catalog(ctx)
	return repos, mapReg(err)
}

// RepoSummary is one row of the repository list.
type RepoSummary struct {
	Name string `json:"name"`
	Tags int    `json:"tags"` // image tags (signature tags not counted)
}

// RepoSummaries lists repositories with their tag counts. Distribution keeps a repository in its
// catalog after its last tag is deleted, so repositories with no tags are left out: that is what
// makes a deleted repository disappear.
func (s *Service) RepoSummaries(ctx context.Context, name string) ([]RepoSummary, error) {
	c, err := s.client(ctx, name)
	if err != nil {
		return nil, err
	}
	repos, err := c.Catalog(ctx)
	if err != nil {
		return nil, mapReg(err)
	}
	out := make([]RepoSummary, len(repos))
	errs := make([]error, len(repos))
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for i, repo := range repos {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, repo string) {
			defer wg.Done()
			defer func() { <-sem }()
			tags, err := c.Tags(ctx, repo)
			if err != nil {
				errs[i] = err
				return
			}
			n := 0
			for _, t := range tags {
				if tagKind(t) == "image" {
					n++
				}
			}
			out[i] = RepoSummary{Name: repo, Tags: n}
		}(i, repo)
	}
	wg.Wait()
	res := make([]RepoSummary, 0, len(repos))
	for i, rs := range out {
		if errs[i] != nil {
			if errors.Is(errs[i], regclient.ErrNotFound) {
				continue // vanished while listing
			}
			return nil, mapReg(errs[i])
		}
		if rs.Tags > 0 {
			res = append(res, rs)
		}
	}
	return res, nil
}

// RepoDeletion reports what DeleteRepository removed.
type RepoDeletion struct {
	Tags      int `json:"tags"`      // image tags that existed
	Manifests int `json:"manifests"` // manifests deleted (an image's signature counts separately)
}

// DeleteRepository removes every image in a repository: the manifest behind each tag, including
// signature indexes, and the stored scan results. Distribution has no repository-level delete, so the
// registry still lists the (now empty) name; RepoSummaries hides it. Disk space is reclaimed by
// garbage collection.
func (s *Service) DeleteRepository(ctx context.Context, name, repo string) (RepoDeletion, error) {
	var res RepoDeletion
	if !regclient.ValidRepo(repo) {
		return res, fmt.Errorf("%w: invalid repository name", ErrInvalid)
	}
	c, err := s.client(ctx, name)
	if err != nil {
		return res, err
	}
	tags, err := c.Tags(ctx, repo)
	if err != nil {
		return res, mapReg(err)
	}
	if len(tags) == 0 {
		return res, ErrNotFound
	}
	seen := map[string]bool{}
	var failed []string
	for _, t := range tags {
		if tagKind(t) == "image" {
			res.Tags++
		}
		d, err := c.Digest(ctx, repo, t)
		if err != nil {
			if !errors.Is(err, regclient.ErrNotFound) {
				failed = append(failed, t)
			}
			continue
		}
		if seen[d] {
			continue // several tags can share one manifest
		}
		seen[d] = true
		if err := c.DeleteManifest(ctx, repo, d); err != nil && !errors.Is(err, regclient.ErrNotFound) {
			failed = append(failed, t)
			continue
		}
		res.Manifests++
	}
	_ = s.st.DeleteScansOfRepo(name, repo)
	if len(failed) > 0 {
		return res, fmt.Errorf("deleted %d of %d manifests; could not delete: %s", res.Manifests, len(seen), strings.Join(failed, ", "))
	}
	return res, nil
}

func (s *Service) Tags(ctx context.Context, name, repo string) ([]TagInfo, error) {
	c, err := s.client(ctx, name)
	if err != nil {
		return nil, err
	}
	tags, err := c.Tags(ctx, repo)
	if err != nil {
		return nil, mapReg(err)
	}
	out := make([]TagInfo, 0, len(tags))
	var live []string
	for _, t := range tags {
		d, err := c.Digest(ctx, repo, t)
		if err != nil {
			return nil, mapReg(err)
		}
		k := tagKind(t)
		out = append(out, TagInfo{Tag: t, Digest: d, Kind: k})
		if k == "image" {
			live = append(live, d)
		}
	}
	if s.sec != nil { // forget results for images that were deleted outside the manager
		_ = s.st.PruneScans(name, repo, live)
	}
	return out, nil
}

// DeleteTag deletes the manifest the tag points at. Every tag sharing that digest disappears too;
// the freed blobs are reclaimed by GC.
func (s *Service) DeleteTag(ctx context.Context, name, repo, tag string) (string, error) {
	c, err := s.client(ctx, name)
	if err != nil {
		return "", err
	}
	d, err := c.Digest(ctx, repo, tag)
	if err != nil {
		return "", mapReg(err)
	}
	if err := c.DeleteManifest(ctx, repo, d); err != nil {
		return "", mapReg(err)
	}
	// Leave nothing behind for the deleted image: its signature index and stored scan results.
	if sd, err := c.Digest(ctx, repo, sigTag(d)); err == nil {
		_ = c.DeleteManifest(ctx, repo, sd)
	}
	_ = s.st.DeleteScansOfDigest(name, repo, d)
	return d, nil
}

// GC stops the registry, collects garbage, and restarts it if it was running.
func (s *Service) GC(ctx context.Context, name string) (res GCResult, err error) {
	rec, err := s.st.Get(name)
	if err != nil {
		return res, err
	}
	mu := lockFor(name)
	mu.Lock()
	defer mu.Unlock()

	st, err := s.drv.Status(ctx, name)
	if err != nil {
		return res, err
	}
	if st.State == runtime.StateMissing {
		return res, runtime.ErrNotFound
	}
	if st.State.Active() {
		if err = s.drv.Stop(ctx, name); err != nil {
			return res, err
		}
		// Always bring it back, even when GC fails.
		defer func() {
			bg := context.WithoutCancel(ctx)
			if rerr := s.drv.Start(bg, name); rerr != nil {
				if err == nil {
					err = fmt.Errorf("gc finished but restart failed: %w", rerr)
				}
				return
			}
			s.waitReady(bg, rec)
		}()
	}

	res.BytesBefore, _ = s.drv.UsedBytes(ctx, name)
	out, gcErr := s.drv.RunGC(ctx, name)
	res.Output = out
	// An empty registry has no repositories dir; nothing to collect.
	if gcErr != nil && strings.Contains(out, "Path not found") {
		gcErr = nil
		res.Output = "nothing to collect (registry is empty)"
	}
	res.BytesAfter, _ = s.drv.UsedBytes(ctx, name)
	return res, gcErr
}

func (s *Service) Usage(ctx context.Context, name string) (int64, error) {
	if _, err := s.st.Get(name); err != nil {
		return 0, err
	}
	return s.drv.UsedBytes(ctx, name)
}
