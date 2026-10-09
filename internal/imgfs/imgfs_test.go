package imgfs

import (
	"archive/tar"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type ent struct {
	name, link string
	typ        byte
	body       string
	mode       int64
}

func mkTar(t *testing.T, es []ent) *bytes.Reader {
	t.Helper()
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for _, e := range es {
		h := &tar.Header{Name: e.name, Typeflag: e.typ, Linkname: e.link, Mode: e.mode, Size: int64(len(e.body))}
		if e.typ == 0 {
			h.Typeflag = tar.TypeReg
		}
		if h.Typeflag != tar.TypeReg {
			h.Size = 0
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Typeflag == tar.TypeReg {
			tw.Write([]byte(e.body))
		}
	}
	tw.Close()
	return bytes.NewReader(b.Bytes())
}

func TestExtractsNormalImage(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "root")
	err := Extract(context.Background(), mkTar(t, []ent{
		{name: "etc/", typ: tar.TypeDir},
		{name: "etc/os-release", body: "ID=rhel\n", mode: 0o644},
		{name: "usr/bin/tool", body: "#!/bin/sh", mode: 0o755},
		{name: "lib64", typ: tar.TypeSymlink, link: "usr/lib64"},
		{name: "usr/lib64/", typ: tar.TypeDir},
		{name: "var/lib/rpm/Packages", body: "db", mode: 0o000}, // unreadable in the image; must stay usable for us
	}), dest, DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dest, "etc/os-release")); string(b) != "ID=rhel\n" {
		t.Fatalf("os-release: %q", b)
	}
	fi, _ := os.Stat(filepath.Join(dest, "usr/bin/tool"))
	if fi.Mode().Perm() != 0o700 {
		t.Fatalf("exec file mode %v", fi.Mode())
	}
	fi, _ = os.Stat(filepath.Join(dest, "var/lib/rpm/Packages"))
	if fi.Mode().Perm()&0o600 != 0o600 {
		t.Fatalf("mode-000 file must remain readable by the extracting user: %v", fi.Mode())
	}
	if l, err := os.Readlink(filepath.Join(dest, "lib64")); err != nil || l != "usr/lib64" {
		t.Fatalf("symlink: %q %v", l, err)
	}
}

func TestHostileArchivesCannotWriteOutside(t *testing.T) {
	base := t.TempDir()
	dest := filepath.Join(base, "root")
	outside := filepath.Join(base, "outside")
	os.MkdirAll(outside, 0o755)
	os.WriteFile(filepath.Join(base, "secret"), []byte("untouched"), 0o600)

	err := Extract(context.Background(), mkTar(t, []ent{
		{name: "../escaped-dotdot", body: "x", mode: 0o644},
		{name: "../../escaped-dotdot2", body: "x", mode: 0o644},
		{name: "/abs-escaped", body: "x", mode: 0o644},          // lands *inside* root, harmless
		{name: "evil", typ: tar.TypeSymlink, link: outside},     // absolute symlink out
		{name: "evil/pwned", body: "x", mode: 0o644},            // write through it
		{name: "rel", typ: tar.TypeSymlink, link: "../outside"}, // relative symlink out
		{name: "rel/pwned2", body: "x", mode: 0o644},
		{name: "sec", typ: tar.TypeLink, link: "../secret"}, // hardlink to a file outside
		{name: "dev/sda", typ: tar.TypeBlock},               // device node
		{name: "fifo", typ: tar.TypeFifo},
		{name: "ok.txt", body: "fine", mode: 0o644},
	}), dest, DefaultLimits)
	if err != nil {
		t.Fatalf("hostile entries must be skipped, not fatal: %v", err)
	}

	entries, _ := os.ReadDir(outside)
	if len(entries) != 0 {
		t.Fatalf("files written outside the target through a symlink: %v", entries)
	}
	for _, p := range []string{"escaped-dotdot", "escaped-dotdot2", "root/../escaped-dotdot"} {
		if _, err := os.Stat(filepath.Join(base, p)); err == nil {
			t.Fatalf("%s escaped", p)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(base, "secret")); string(b) != "untouched" {
		t.Fatal("outside file modified")
	}
	if _, err := os.Lstat(filepath.Join(dest, "sec")); err == nil {
		t.Fatal("hardlink to an outside file was created")
	}
	for _, special := range []string{"dev/sda", "fifo"} {
		if _, err := os.Lstat(filepath.Join(dest, special)); err == nil {
			t.Fatalf("special file %s created", special)
		}
	}
	if b, err := os.ReadFile(filepath.Join(dest, "ok.txt")); err != nil || string(b) != "fine" {
		t.Fatalf("legitimate file lost after hostile entries: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(dest, "abs-escaped")); string(b) != "x" {
		t.Fatal("absolute name should be confined inside the root")
	}
}

func TestLimits(t *testing.T) {
	big := strings.Repeat("a", 2048)
	err := Extract(context.Background(), mkTar(t, []ent{{name: "a", body: big, mode: 0o644}, {name: "b", body: big, mode: 0o644}}),
		filepath.Join(t.TempDir(), "r"), Limits{MaxBytes: 3000, MaxEntries: 10})
	if err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("size cap: %v", err)
	}
	var es []ent
	for i := 0; i < 20; i++ {
		es = append(es, ent{name: "f" + string(rune('a'+i)), body: "x", mode: 0o644})
	}
	err = Extract(context.Background(), mkTar(t, es), filepath.Join(t.TempDir(), "r"), Limits{MaxBytes: 1 << 20, MaxEntries: 5})
	if err == nil || !strings.Contains(err.Error(), "more than") {
		t.Fatalf("entry cap: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Extract(ctx, mkTar(t, []ent{{name: "a", body: "x"}}), filepath.Join(t.TempDir(), "r"), DefaultLimits); err == nil {
		t.Fatal("cancelled context ignored")
	}
}
