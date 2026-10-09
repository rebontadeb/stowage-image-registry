package service

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	gort "runtime"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/rdeb/local-image-registry/internal/regclient"
)

// RebaseInput asks Stowage to move an image onto a newer base image.
type RebaseInput struct {
	Repo    string `json:"repo"`
	Ref     string `json:"ref"`     // tag of the image to rebase
	OldBase string `json:"oldBase"` // the base the image was built on, e.g. docker.io/library/nginx:1.21.4-alpine
	// BaseLayers, when set, says that the first N layers of the image are its base. Use it when the old base's
	// tag has been rebuilt since the image was made, so the old base can no longer be matched layer by layer.
	BaseLayers int    `json:"baseLayers"`
	NewBase    string `json:"newBase"` // the base to move to, e.g. docker.io/library/nginx:1.27-alpine
	Tag        string `json:"tag"`     // new tag; default <ref>-rebased
	Username   string `json:"username"`
	Password   string `json:"password"`
	SkipTLS    bool   `json:"skipTLS"`
	Overwrite  bool   `json:"overwrite"`
}

// RebaseImage builds a copy of an image whose own layers sit on NewBase instead of OldBase and pushes it as a
// new tag. The original is not modified. The application layers are carried over as they are.
func (s *Service) RebaseImage(ctx context.Context, registry string, in RebaseInput, by string) (TransferView, error) {
	if !regclient.ValidRepo(in.Repo) {
		return TransferView{}, fmt.Errorf("%w: invalid repository name", ErrInvalid)
	}
	if in.Ref == "" || len(in.Ref) > 200 {
		return TransferView{}, fmt.Errorf("%w: give the tag of the image to rebase", ErrInvalid)
	}
	var oldRef name.Reference
	if in.BaseLayers < 0 || in.BaseLayers > 200 {
		return TransferView{}, fmt.Errorf("%w: base layers must be a small positive number", ErrInvalid)
	}
	if in.BaseLayers == 0 || strings.TrimSpace(in.OldBase) != "" {
		var err error
		if oldRef, err = parseBase(in.OldBase); err != nil {
			return TransferView{}, fmt.Errorf("%w: old base: %v", ErrInvalid, err)
		}
	}
	newRef, err := parseBase(in.NewBase)
	if err != nil {
		return TransferView{}, fmt.Errorf("%w: new base: %v", ErrInvalid, err)
	}
	if oldRef != nil && oldRef.String() == newRef.String() {
		return TransferView{}, fmt.Errorf("%w: the new base is the same as the old one", ErrInvalid)
	}
	newTag := in.Tag
	if newTag == "" {
		newTag = in.Ref + "-rebased"
	}
	if newTag == in.Ref {
		return TransferView{}, fmt.Errorf("%w: the rebased image needs a different tag than the original", ErrInvalid)
	}
	c, err := s.client(ctx, registry)
	if err != nil {
		return TransferView{}, err
	}
	digest := in.Ref
	if !digestRe.MatchString(digest) {
		if digest, err = c.Digest(ctx, in.Repo, in.Ref); err != nil {
			return TransferView{}, mapReg(err)
		}
	}
	a, err := s.prepare(ctx, registry, in.Repo, newTag, in.Overwrite)
	if err != nil {
		return TransferView{}, err
	}
	job, err := s.tr.newJob("rebase", registry, in.Repo, newTag, in.NewBase, by)
	if err != nil {
		return TransferView{}, err
	}
	view := *job
	go s.run(job.ID, true, func(ctx context.Context, progress func(done, total int64)) (string, error) {
		return s.doRebase(ctx, a, in, digest, newTag, oldRef, newRef, progress)
	})
	return view, nil
}

func parseBase(s string) (name.Reference, error) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 512 {
		return nil, errors.New("give an image reference, e.g. docker.io/library/nginx:1.27-alpine")
	}
	return name.ParseReference(s)
}

func (s *Service) doRebase(ctx context.Context, a access, in RebaseInput, digest, newTag string, oldRef, newRef name.Reference, progress func(done, total int64)) (string, error) {
	opts := s.baseOptions(ctx, in)

	orig, err := s.sourceImage(ctx, a, in.Repo, digest)
	if err != nil {
		return "", err
	}
	var oldBase v1.Image
	if in.BaseLayers == 0 {
		if oldBase, err = remote.Image(oldRef, opts...); err != nil {
			return "", fmt.Errorf("old base %s: %w", in.OldBase, err)
		}
	}
	newBase, err := remote.Image(newRef, opts...)
	if err != nil {
		return "", fmt.Errorf("new base %s: %w", in.NewBase, err)
	}
	img, err := rebaseOnto(orig, oldBase, newBase, in.BaseLayers)
	if errors.Is(err, errNotOnBase) {
		return "", fmt.Errorf("%w: this image is not built on %s: its layers do not start with that image's layers, so it cannot be moved. Check the old base", ErrInvalid, in.OldBase)
	}
	if err != nil {
		return "", err
	}
	cfg, err := img.ConfigFile()
	if err != nil {
		return "", err
	}
	cfg = cfg.DeepCopy()
	if cfg.Config.Labels == nil {
		cfg.Config.Labels = map[string]string{}
	}
	cfg.Config.Labels["io.stowage.rebased-from"] = digest
	cfg.Config.Labels["io.stowage.base"] = in.NewBase
	if img, err = mutate.ConfigFile(img, cfg); err != nil {
		return "", err
	}
	size, err := imageSize(img)
	if err != nil {
		return "", err
	}
	if size > s.tr.limit {
		return "", fmt.Errorf("%w: the rebased image is %s, above the %s limit", ErrInvalid, humanBytes(size), humanBytes(s.tr.limit))
	}
	dst, dstOpts, err := s.destination(a, in.Repo, newTag)
	if err != nil {
		return "", err
	}
	progOpt, stop := pushProgress(progress)
	defer stop()
	if err := remote.Write(dst, img, append(dstOpts, remote.WithContext(ctx), progOpt)...); err != nil {
		return "", err
	}
	d, err := img.Digest()
	return d.String(), err
}

var errNotOnBase = errors.New("image is not based on the old base")

// rebaseOnto returns orig with the layers of oldBase swapped for those of newBase. Layers are matched by
// their uncompressed content (diff ID): a registry or a push may recompress a layer, which changes its
// compressed digest but not what it contains. The image's own configuration (user, entrypoint, environment,
// labels) is kept.
//
// With baseLayers > 0 the first baseLayers layers are taken as the base without comparing them to oldBase.
func rebaseOnto(orig, oldBase, newBase v1.Image, baseLayers int) (v1.Image, error) {
	oc, err := orig.ConfigFile()
	if err != nil {
		return nil, err
	}
	nc, err := newBase.ConfigFile()
	if err != nil {
		return nil, err
	}
	n := baseLayers
	if n > 0 {
		if n >= len(oc.RootFS.DiffIDs) {
			return nil, fmt.Errorf("%w: the image has %d layers, so at most %d of them can be its base", ErrInvalid, len(oc.RootFS.DiffIDs), len(oc.RootFS.DiffIDs)-1)
		}
	} else {
		bc, err := oldBase.ConfigFile()
		if err != nil {
			return nil, err
		}
		n = len(bc.RootFS.DiffIDs)
		if n == 0 || len(oc.RootFS.DiffIDs) < n {
			return nil, errNotOnBase
		}
		for i := 0; i < n; i++ {
			if oc.RootFS.DiffIDs[i] != bc.RootFS.DiffIDs[i] {
				return nil, errNotOnBase
			}
		}
	}
	layers, err := orig.Layers()
	if err != nil {
		return nil, err
	}
	// history entries that belong to the old base: up to and including the one that made its last layer
	cut, seen := len(oc.History), 0
	for i, h := range oc.History {
		if !h.EmptyLayer {
			if seen++; seen == n {
				cut = i + 1
				break
			}
		}
	}
	var app []mutate.Addendum
	own := oc.History[cut:]
	k := 0
	for _, h := range own {
		if h.EmptyLayer {
			continue
		}
		if n+k >= len(layers) {
			break
		}
		app = append(app, mutate.Addendum{Layer: layers[n+k], History: h})
		k++
	}
	for ; n+k < len(layers); k++ {
		app = append(app, mutate.Addendum{Layer: layers[n+k]})
	}
	img := newBase
	if len(app) > 0 {
		if img, err = mutate.Append(newBase, app...); err != nil {
			return nil, err
		}
	}
	cfg, err := img.ConfigFile()
	if err != nil {
		return nil, err
	}
	cfg = cfg.DeepCopy()
	cfg.Config = oc.Config
	cfg.History = append(append([]v1.History{}, nc.History...), own...)
	return mutate.ConfigFile(img, cfg)
}

// BaseCheck is the result of CheckRebaseBase.
type BaseCheck struct {
	Matches     bool `json:"matches"`
	BaseLayers  int  `json:"baseLayers"`
	ImageLayers int  `json:"imageLayers"`
	Common      int  `json:"common"` // leading layers the image and the base share
	// History is how the image was built (the Dockerfile steps, shortened), oldest first.
	History []string `json:"history"`
}

// CheckRebaseBase says whether an image is built on the given base, without changing anything.
func (s *Service) CheckRebaseBase(ctx context.Context, registry, repo, ref, oldBase string, in RebaseInput) (BaseCheck, error) {
	if !regclient.ValidRepo(repo) || ref == "" || len(ref) > 200 {
		return BaseCheck{}, fmt.Errorf("%w: invalid repository or tag", ErrInvalid)
	}
	oldRef, err := parseBase(oldBase)
	if err != nil {
		return BaseCheck{}, fmt.Errorf("%w: base: %v", ErrInvalid, err)
	}
	c, err := s.client(ctx, registry)
	if err != nil {
		return BaseCheck{}, err
	}
	digest := ref
	if !digestRe.MatchString(digest) {
		if digest, err = c.Digest(ctx, repo, ref); err != nil {
			return BaseCheck{}, mapReg(err)
		}
	}
	a, err := s.toolAccess(ctx, registry)
	if err != nil {
		return BaseCheck{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	opts := s.baseOptions(ctx, in)
	orig, err := s.sourceImage(ctx, a, repo, digest)
	if err != nil {
		return BaseCheck{}, err
	}
	base, err := remote.Image(oldRef, opts...)
	if err != nil {
		return BaseCheck{}, fmt.Errorf("%w: base %s: %s", ErrInvalid, oldBase, userError(err))
	}
	oc, err := orig.ConfigFile()
	if err != nil {
		return BaseCheck{}, err
	}
	bc, err := base.ConfigFile()
	if err != nil {
		return BaseCheck{}, err
	}
	res := BaseCheck{BaseLayers: len(bc.RootFS.DiffIDs), ImageLayers: len(oc.RootFS.DiffIDs)}
	for res.Common < res.BaseLayers && res.Common < res.ImageLayers && oc.RootFS.DiffIDs[res.Common] == bc.RootFS.DiffIDs[res.Common] {
		res.Common++
	}
	res.Matches = res.BaseLayers > 0 && res.Common == res.BaseLayers
	layerNo := 0
	for _, h := range oc.History {
		line := strings.Join(strings.Fields(strings.TrimPrefix(h.CreatedBy, "/bin/sh -c #(nop) ")), " ")
		if len(line) > 140 {
			line = line[:140] + "…"
		}
		if h.EmptyLayer {
			line = "      " + line
		} else {
			layerNo++
			line = fmt.Sprintf("#%-2d   %s", layerNo, line)
		}
		if len(res.History) < 80 {
			res.History = append(res.History, line)
		}
	}
	return res, nil
}

// baseOptions are the remote options for reading base images: no loopback targets, optional credentials.
func (s *Service) baseOptions(ctx context.Context, in RebaseInput) []remote.Option {
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
	return []remote.Option{remote.WithContext(ctx), remote.WithAuth(auth), remote.WithTransport(tr),
		remote.WithPlatform(v1.Platform{OS: "linux", Architecture: gort.GOARCH})}
}
