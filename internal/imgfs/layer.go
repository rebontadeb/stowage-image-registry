package imgfs

import (
	"archive/tar"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// Snapshot records enough about an unpacked tree to tell later which entries changed.
type Snapshot map[string]fileState

type fileState struct {
	mode   fs.FileMode
	size   int64
	mtime  int64
	target string // symlink target
}

// skipped paths hold caches and logs a package manager leaves behind; they must not become image content.
var skipped = []string{"var/cache", "var/log", "tmp", "run"}

func isSkipped(rel string) bool {
	for _, p := range skipped {
		if rel == p || strings.HasPrefix(rel, p+"/") {
			return true
		}
	}
	return false
}

func walk(dir string, f func(rel string, fi fs.FileInfo, target string) error) error {
	return filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil || rel == "." {
			return err
		}
		rel = filepath.ToSlash(rel)
		if isSkipped(rel) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		target := ""
		if fi.Mode()&fs.ModeSymlink != 0 {
			if target, err = os.Readlink(p); err != nil {
				return err
			}
		}
		return f(rel, fi, target)
	})
}

// TakeSnapshot records the tree below dir (without following symlinks).
func TakeSnapshot(dir string) (Snapshot, error) {
	s := Snapshot{}
	err := walk(dir, func(rel string, fi fs.FileInfo, target string) error {
		s[rel] = fileState{mode: fi.Mode(), size: fi.Size(), mtime: fi.ModTime().UnixNano(), target: target}
		return nil
	})
	return s, err
}

// WriteLayer writes an uncompressed OCI layer tar holding what differs between dir and before: new and
// changed files, symlinks and new directories, plus whiteouts for what was removed. All entries are
// owned by root, matching package-manager output. It returns how many entries were written.
func WriteLayer(dir string, before Snapshot, w io.Writer) (int, error) {
	tw := tar.NewWriter(w)
	seen := map[string]bool{}
	n := 0
	err := walk(dir, func(rel string, fi fs.FileInfo, target string) error {
		seen[rel] = true
		old, existed := before[rel]
		now := fileState{mode: fi.Mode(), size: fi.Size(), mtime: fi.ModTime().UnixNano(), target: target}
		if existed && (fi.IsDir() && old.mode.IsDir() || old == now) {
			return nil
		}
		h := &tar.Header{Name: rel, Mode: tarMode(fi.Mode()), ModTime: fi.ModTime(), Format: tar.FormatPAX}
		switch {
		case fi.IsDir():
			h.Typeflag = tar.TypeDir
			h.Name += "/"
		case fi.Mode()&fs.ModeSymlink != 0:
			h.Typeflag, h.Linkname = tar.TypeSymlink, target
		case fi.Mode().IsRegular():
			h.Typeflag, h.Size = tar.TypeReg, fi.Size()
		default:
			return nil // devices, sockets, fifos are never part of a layer
		}
		if existed && !old.mode.IsDir() && fi.IsDir() { // a file became a directory: remove the file first
			if err := tw.WriteHeader(&tar.Header{Name: whiteout(rel), Typeflag: tar.TypeReg, Mode: 0o600, Format: tar.FormatPAX}); err != nil {
				return err
			}
		}
		if err := tw.WriteHeader(h); err != nil {
			return err
		}
		if h.Typeflag == tar.TypeReg {
			f, err := os.Open(filepath.Join(dir, filepath.FromSlash(rel)))
			if err != nil {
				return err
			}
			_, err = io.CopyN(tw, f, h.Size)
			f.Close()
			if err != nil {
				return fmt.Errorf("imgfs: %s: %w", rel, err)
			}
		}
		n++
		return nil
	})
	if err != nil {
		return n, err
	}
	var gone []string
	for rel := range before {
		if !seen[rel] {
			gone = append(gone, rel)
		}
	}
	sort.Strings(gone)
	for _, rel := range gone {
		if parent := path.Dir(rel); parent != "." && !seen[parent] {
			continue // the whole directory is gone: one whiteout for it is enough
		}
		if err := tw.WriteHeader(&tar.Header{Name: whiteout(rel), Typeflag: tar.TypeReg, Mode: 0o600, Format: tar.FormatPAX}); err != nil {
			return n, err
		}
		n++
	}
	return n, tw.Close()
}

func whiteout(rel string) string { return path.Join(path.Dir(rel), ".wh."+path.Base(rel)) }

// tarMode keeps the permission bits and the setuid/setgid/sticky flags.
func tarMode(m fs.FileMode) int64 {
	v := int64(m.Perm())
	if m&fs.ModeSetuid != 0 {
		v |= 0o4000
	}
	if m&fs.ModeSetgid != 0 {
		v |= 0o2000
	}
	if m&fs.ModeSticky != 0 {
		v |= 0o1000
	}
	return v
}
