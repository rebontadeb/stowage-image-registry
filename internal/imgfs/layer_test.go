package imgfs

import (
	"archive/tar"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func put(t *testing.T, dir, rel, body string, mt time.Time) {
	t.Helper()
	p := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(p, mt, mt); err != nil {
		t.Fatal(err)
	}
}

func TestWriteLayerHoldsOnlyWhatChanged(t *testing.T) {
	dir := t.TempDir()
	t0 := time.Unix(1_700_000_000, 0)
	put(t, dir, "usr/lib/libc.so", "old", t0)
	put(t, dir, "usr/lib/keep", "same", t0)
	put(t, dir, "etc/gone", "x", t0)
	put(t, dir, "var/lib/dead/a", "x", t0)
	put(t, dir, "var/cache/dnf/junk", "x", t0)
	before, err := TakeSnapshot(dir)
	if err != nil {
		t.Fatal(err)
	}

	put(t, dir, "usr/lib/libc.so", "newer!", t0.Add(time.Hour)) // replaced
	put(t, dir, "usr/bin/new", "bin", t0)                       // added
	put(t, dir, "var/cache/dnf/more", "junk", t0)               // ignored
	os.Remove(filepath.Join(dir, "etc/gone"))
	os.RemoveAll(filepath.Join(dir, "var/lib/dead"))
	if err := os.Symlink("libc.so", filepath.Join(dir, "usr/lib/link")); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if _, err := WriteLayer(dir, before, &buf); err != nil {
		t.Fatal(err)
	}
	got := map[string]*tar.Header{}
	bodies := map[string]string{}
	tr := tar.NewReader(&buf)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(tr)
		got[h.Name], bodies[h.Name] = h, string(b)
		if h.Uid != 0 || h.Gid != 0 {
			t.Errorf("%s not owned by root", h.Name)
		}
	}
	for _, want := range []string{"usr/lib/libc.so", "usr/bin/new", "usr/lib/link", "etc/.wh.gone", "var/lib/.wh.dead"} {
		if got[want] == nil {
			t.Errorf("layer lacks %s; has %v", want, keys(got))
		}
	}
	for _, not := range []string{"usr/lib/keep", "var/cache/dnf/more", "var/cache/dnf/junk", "var/lib/dead/.wh.a"} {
		if got[not] != nil {
			t.Errorf("layer must not contain %s", not)
		}
	}
	if bodies["usr/lib/libc.so"] != "newer!" || got["usr/lib/link"].Linkname != "libc.so" {
		t.Errorf("wrong content: %q %q", bodies["usr/lib/libc.so"], got["usr/lib/link"].Linkname)
	}
}

func keys(m map[string]*tar.Header) (k []string) {
	for n := range m {
		k = append(k, n)
	}
	return
}
