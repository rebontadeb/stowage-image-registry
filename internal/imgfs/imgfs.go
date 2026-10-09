// Package imgfs unpacks a container image's filesystem into a directory, safely. Image layers are
// untrusted input: entries are confined to the target with os.Root (no ".." and no symlink can lead
// outside it), special files are skipped, and total size and entry counts are capped.
package imgfs

import (
	"archive/tar"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
)

type Limits struct {
	MaxBytes   int64 // total regular-file bytes
	MaxEntries int
}

var DefaultLimits = Limits{MaxBytes: 6 << 30, MaxEntries: 1_000_000}

type Source struct {
	Ref      string // host:port/repo@sha256:...
	Username string
	Password string
	HTTP     bool // plain-HTTP registry
	SkipTLS  bool // self-signed registry certificate
}

// Pull streams the flattened filesystem of the image (whiteouts applied) into dest.
func Pull(ctx context.Context, src Source, dest string, lim Limits) error {
	opts := []crane.Option{crane.WithContext(ctx)}
	if src.Username != "" {
		opts = append(opts, crane.WithAuth(authn.FromConfig(authn.AuthConfig{Username: src.Username, Password: src.Password})))
	}
	if src.HTTP {
		opts = append(opts, crane.Insecure)
	}
	if src.SkipTLS {
		opts = append(opts, crane.WithTransport(&http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}))
	}
	if _, err := name.ParseReference(src.Ref, name.WeakValidation); err != nil {
		return fmt.Errorf("imgfs: bad reference: %w", err)
	}
	img, err := crane.Pull(src.Ref, opts...)
	if err != nil {
		return fmt.Errorf("imgfs: pull: %w", err)
	}
	pr, pw := io.Pipe()
	go func() { pw.CloseWithError(crane.Export(img, pw)) }()
	defer pr.Close()
	return Extract(ctx, pr, dest, lim)
}

// Extract unpacks a tar stream into dest (created if needed).
func Extract(ctx context.Context, r io.Reader, dest string, lim Limits) error {
	if err := os.MkdirAll(dest, 0o700); err != nil {
		return err
	}
	root, err := os.OpenRoot(dest)
	if err != nil {
		return err
	}
	defer root.Close()

	tr := tar.NewReader(r)
	var total int64
	entries := 0
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("imgfs: bad archive: %w", err)
		}
		if entries++; entries > lim.MaxEntries {
			return fmt.Errorf("imgfs: image has more than %d files", lim.MaxEntries)
		}
		rel := strings.TrimPrefix(path.Clean("/"+h.Name), "/")
		if rel == "" {
			continue
		}
		switch h.Typeflag {
		case tar.TypeDir:
			_ = root.MkdirAll(rel, 0o700)
		case tar.TypeReg:
			if total += h.Size; total > lim.MaxBytes {
				return fmt.Errorf("imgfs: image is larger than %d bytes", lim.MaxBytes)
			}
			if err := writeFile(root, rel, tr, h); err != nil {
				return err
			}
		case tar.TypeSymlink:
			_ = root.MkdirAll(path.Dir(rel), 0o700)
			_ = root.Remove(rel)
			_ = root.Symlink(h.Linkname, rel) // target is only ever interpreted inside root
		case tar.TypeLink:
			target := strings.TrimPrefix(path.Clean("/"+h.Linkname), "/")
			_ = root.MkdirAll(path.Dir(rel), 0o700)
			_ = root.Remove(rel)
			_ = root.Link(target, rel)
		default: // devices, fifos, ...: never created
		}
	}
}

func writeFile(root *os.Root, rel string, r io.Reader, h *tar.Header) error {
	if err := root.MkdirAll(path.Dir(rel), 0o700); err != nil {
		return nil // parent blocked (e.g. through an escaping symlink): skip the entry
	}
	_ = root.Remove(rel)
	mode := os.FileMode(0o600)
	if h.Mode&0o111 != 0 {
		mode = 0o700
	}
	f, err := root.OpenFile(rel, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return nil // refused by os.Root: skip, never write outside
	}
	defer f.Close()
	if _, err := io.CopyN(f, r, h.Size); err != nil {
		return fmt.Errorf("imgfs: %s: %w", rel, err)
	}
	return nil
}
